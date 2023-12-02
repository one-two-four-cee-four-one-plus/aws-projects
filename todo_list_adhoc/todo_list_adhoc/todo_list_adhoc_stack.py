from ast import parse, unparse
from os import system, getcwd
from inspect import getsource
from textwrap import dedent
from urllib.request import urlopen
from pathlib import Path

from aws_cdk import *


base_page = '''
<!doctype html>
<html>
  <head>
    <script src="/htmx.min.js"></script><script src="/cognito.js"></script>
    <script>
      const idp_cid = '[[IDP_CLIENT_ID]]';
      const idp_pid = '[[IDP_POOL_ID]]';
      const userPool = new AmazonCognitoIdentity.CognitoUserPool({
          UserPoolId: idp_pid,
          ClientId: idp_cid
      });

      const signUp = (username, password) => new Promise((resolve, reject) => {
        userPool.signUp(username, password, [], null, (err, res) => {(err) ? reject(err) : resolve(res)})
      });

      const signIn = (username, password) => new Promise((resolve, reject) => {
        let authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails({
            Username: username, Password: password
        });
        let cognitoUser = new AmazonCognitoIdentity.CognitoUser({
            Username: username, Pool: userPool,
        });
        cognitoUser.setAuthenticationFlowType('USER_PASSWORD_AUTH');
        cognitoUser.authenticateUser(authenticationDetails, {
            onSuccess: result => resolve(result),
            onFailure: err => reject(err)
        });
      });

      const get_cookie = (name) => {
          let cookieArray = document.cookie.split(';');
          for(let i = 0; i < cookieArray.length; i++) {
              let cookiePair = cookieArray[i].split('=');
              if(name == cookiePair[0].trim()) {
                  return decodeURIComponent(cookiePair[1]);
              }
          }
          return null;
      }

      const _signInOrUp = async (username, password) => {
        let result = get_cookie('jwt');

        if (!result) {
            try {
                result = await signIn(username, password);
                result = result.getIdToken().getJwtToken();
            } catch (err) {
                if (err.code === 'UserNotFoundException') {
                    await signUp(username, password);
                    result = await signIn(username, password);
                    result = result.getIdToken().getJwtToken();
                } else {
                    throw err;
                }
            }
        }

        return result;
      };

      const signInOrUp = (username, password) => {
        _signInOrUp(username, password).then(result => {
            document.cookie = `jwt=${result}; path=/`;
            document.getElementById('login-form').classList.add('hidden');
            document.getElementById('list').classList.remove('hidden');
            document.getElementById('refresh-btn').click();
        })
      };

      document.addEventListener('htmx:configRequest', (event) => {
          event.detail.headers['Authorization'] = `Bearer ${get_cookie('jwt')}`;
      });

      document.addEventListener('htmx:responseError', (event) => {
            console.log(JSON.stringify(event.detail));
      });

      window.addEventListener("load", () => {
          if (get_cookie('jwt')) {
              document.getElementById('login-form').classList.add('hidden');
              document.getElementById('list').classList.remove('hidden');
          }
      });
  </script>
  </head>
  <body>
  [[BODY]]
  </body>
</html>
'''
base_index = base_page.replace('[[BODY]]', '''
    <style>.hidden {display: none;}</style>
    <form id="login-form" onsubmit="signInOrUp(this.username.value, this.password.value); return false;">
        <input type="text" name="username" required />
        <input type="password" name="password" required />
        <button type="submit">Login</button>
    </form>

    <div id="list" class="hidden">
        <form hx-post="/api/items" hx-target="#todo-list" hx-swap="beforeend">
            <input type="text" name="item" required />
            <button type="submit">Add</button>
        </form>

        <button id="refresh-btn" hx-get="/api/items" hx-target="#todo-list" hx-swap="innerHTML">&#x21bb;</button>
        <ul id="todo-list">
            <li hx-get="/api/items" hx-target="#todo-list" hx-swap="innerHTML" hx-trigger="load">
                <span hx-ext="text">Loading...</span>
            </li>
        </ul>
    </div>
''')
error = '''
    <p>Something went wrong.</p>
'''


class TodoListAdhocStack(Stack):

    def __init__(self, scope, construct_id, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        pool = aws_cognito.UserPool(
            self, 'pool', removal_policy=RemovalPolicy.DESTROY,
            self_sign_up_enabled=True
        )

        def autosignup(event, context):
            event['response']['autoConfirmUser'] = True
            return event

        pool.add_trigger(
            aws_cognito.UserPoolOperation.PRE_SIGN_UP,
            aws_lambda.Function(
                self, 'autosignup', runtime=aws_lambda.Runtime.PYTHON_3_8,
                handler='index.autosignup', code=aws_lambda.Code.from_inline(dedent(getsource(autosignup))),
                memory_size=1024
            )
        )

        api = aws_apigateway.RestApi(
            self, 'api',
            default_cors_preflight_options=aws_apigateway.CorsOptions(
                allow_origins=aws_apigateway.Cors.ALL_ORIGINS,
                allow_methods=aws_apigateway.Cors.ALL_METHODS,
            ),
            default_method_options=aws_apigateway.MethodOptions(
                authorization_type=aws_apigateway.AuthorizationType.COGNITO,
                authorizer=aws_apigateway.CognitoUserPoolsAuthorizer(
                    self, 'auth', cognito_user_pools=[pool],
                    identity_source='method.request.header.Authorization',
                    results_cache_ttl=Duration.seconds(0),
                ),
            ),
        )

        table = aws_dynamodb.Table(
            self, 'table', partition_key=aws_dynamodb.Attribute(
                name='uuid',
                type=aws_dynamodb.AttributeType.STRING
            ),
            removal_policy=RemovalPolicy.DESTROY,
        )
        table.add_global_secondary_index(
            partition_key=aws_dynamodb.Attribute(
                name='user',
                type=aws_dynamodb.AttributeType.STRING
            ),
            index_name='user-index'
        )
        client = pool.add_client('client', auth_flows=aws_cognito.AuthFlow(user_password=True))

        index = (base_index
                 .replace('[[IDP_CLIENT_ID]]', client.user_pool_client_id)
                 .replace('[[IDP_POOL_ID]]', pool.user_pool_id))
        site_bucket = aws_s3.Bucket(
            self, 'site_bucket', public_read_access=True,
            block_public_access=aws_s3.BlockPublicAccess(
                block_public_acls=False, block_public_policy=False,
                ignore_public_acls=False, restrict_public_buckets=False
            ),
            website_index_document='index.html', website_error_document='error.html',
            removal_policy=RemovalPolicy.DESTROY,
        )
        cwd = Path(__file__).parent
        if not (cwd / 'htmx.min.js').exists():
            print('Downloading htmx.min.js')
            with urlopen('https://unpkg.com/htmx.org/dist/htmx.min.js') as f:
                htmx = f.read().decode()
            (cwd / 'htmx.min.js').write_text(htmx)
        if not (cwd / 'cognito.js').exists():
            print('Downloading cognito.js')
            origin = getcwd()
            system(
                f'cd {cwd}/.. && '
                f'npm i amazon-cognito-identity-js &&'
                f'cp node_modules/amazon-cognito-identity-js/dist/amazon-cognito-identity.min.js {cwd}/cognito.js &&'
                f'cd {origin}'
            )
        cf = aws_cloudfront.Distribution(
            self, 'distro',
            default_behavior=aws_cloudfront.BehaviorOptions(
                origin=aws_cloudfront_origins.S3Origin(site_bucket),
            ),
            additional_behaviors={
                'api/*': aws_cloudfront.BehaviorOptions(
                    origin=aws_cloudfront_origins.RestApiOrigin(api),
                    allowed_methods=aws_cloudfront.AllowedMethods.ALLOW_ALL,
                    cache_policy=aws_cloudfront.CachePolicy.CACHING_DISABLED,
                    origin_request_policy=aws_cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER
                )
            },
        )
        aws_s3_deployment.BucketDeployment(
            self, 'static_site', sources=[
                aws_s3_deployment.Source.data('index.html', index),
                aws_s3_deployment.Source.data('error.html', error),
                aws_s3_deployment.Source.data('htmx.min.js', (cwd / 'htmx.min.js').read_text()),
                aws_s3_deployment.Source.data('cognito.js', (cwd / 'cognito.js').read_text()),
            ],
            destination_bucket=site_bucket,
            distribution=cf,
        )

        ping_rule = aws_events.Rule(
            self, 'PingRule', schedule=aws_events.Schedule.rate(Duration.minutes(2))
        )

        def get_body(fun):
            body = parse(dedent(getsource(fun)))
            return '\n'.join([unparse(line) for line in body.body[0].body])

        def rest_endpoint(method, resource):
            def closure(handler):
                fun = aws_lambda.Function(
                    self, handler.__name__, runtime=aws_lambda.Runtime.PYTHON_3_8,
                    handler='index.handler', code=aws_lambda.Code.from_inline(get_body(handler)),
                    environment={'TABLE': table.table_name}, memory_size=1024
                )
                table.grant_read_write_data(fun)
                ping_rule.add_target(aws_events_targets.LambdaFunction(fun))
                resource.add_method(method.upper(), aws_apigateway.LambdaIntegration(fun))
            return closure

        api_root = api.root.add_resource('api')
        items = api_root.add_resource('items')
        item = items.add_resource('{uuid}')

        @rest_endpoint('get', items)
        def list_items():
            import os
            import boto3
            from boto3.dynamodb.conditions import Key

            table = boto3.resource('dynamodb').Table(os.environ['TABLE'])

            def handler(event, context):
                sub = event['requestContext']['authorizer']['claims']['sub']
                body = ''
                items = table.query(IndexName='user-index', KeyConditionExpression=Key('user').eq(sub))
                for item in items['Items']:
                    uuid, item = item['uuid'], item['item']
                    body += f'''
                    <li id="item-{uuid}">
                      <form  hx-delete="/api/items/{uuid}" hx-target="#item-{uuid}" hx-swap="outerHTML">
                        {item}
                        <button type="submit">Remove</button>
                      </form>
                    </li>
                    '''

                return {
                    'statusCode': 200,
                    'body': body
                }

        @rest_endpoint('post', items)
        def add_item(event, context):
            import os
            import boto3
            from uuid import uuid4
            from urllib.parse import parse_qs

            table = boto3.resource('dynamodb').Table(os.environ['TABLE'])

            def handler(event, context):
                sub = event['requestContext']['authorizer']['claims']['sub']
                uuid = str(uuid4())
                item = parse_qs(event['body'])['item'][0]
                table.put_item(Item={'uuid': uuid, 'item': item, 'user': sub})
                body = f'''
                <li id="item-{uuid}">
                  <form  hx-delete="/api/items/{uuid}" hx-target="#item-{uuid}" hx-swap="outerHTML">
                    {item}
                    <button type="submit">Remove</button>
                  </form>
                </li>
                '''
                return {
                    'statusCode': 200,
                    'body': body
                }

        @rest_endpoint('delete', item)
        def delete_item():
            import os
            import boto3

            table = boto3.resource('dynamodb').Table(os.environ['TABLE'])

            def handler(event, context):
                table.delete_item(Key={'uuid': event['pathParameters']['uuid']})

                return {
                    'statusCode': 200,
                    'body': ''
                }

        CfnOutput(self, 'site_url', value=cf.domain_name)
