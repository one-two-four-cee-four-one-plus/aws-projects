FROM python:latest
RUN useradd -m melvin \
    && apt update -y \
    && apt install nodejs npm less jq fish -y \
    && chsh -s /usr/bin/fish melvin \
    && npm install -g aws-cdk \
    && python -m pip install aws-cdk-lib constructs IPython boto3 \
    && curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
    && unzip awscliv2.zip \
    && ./aws/install
ENV PYTHONDONTWRITEBYTECODE=1
WORKDIR /aws
USER melvin
CMD sleep inf
