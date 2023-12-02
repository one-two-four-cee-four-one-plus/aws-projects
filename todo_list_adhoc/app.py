#!/usr/bin/env python3
import os

import aws_cdk as cdk

from todo_list_adhoc.todo_list_adhoc_stack import TodoListAdhocStack


app = cdk.App()
TodoListAdhocStack(app, "TodoListAdhocStack")
app.synth()
