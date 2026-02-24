#!/usr/bin/env bash

juju add-model kubeflow
juju model-config logging-config="<root>=WARNING;unit=DEBUG"
juju deploy ./s3-integrator_ubuntu@24.04-amd64.charm

SECRET_ID=$(juju add-secret creds access-key=foo secret-key=bar)
juju grant-secret creds s3-integrator
juju config s3-integrator endpoint=http://192.168.250.250 credentials=${SECRET_ID} bucket=manos

