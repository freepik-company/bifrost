# Bifrost
![GitHub go.mod Go version (subdirectory of monorepo)](https://img.shields.io/github/go-mod/go-version/freepik-company/bifrost)
![GitHub](https://img.shields.io/github/license/freepik-company/bifrost)

![YouTube Channel Subscribers](https://img.shields.io/youtube/channel/subscribers/UCeSb3yfsPNNVr13YsYNvCAw?label=achetronic&link=http%3A%2F%2Fyoutube.com%2Fachetronic)
![X (formerly Twitter) Follow](https://img.shields.io/twitter/follow/achetronic?style=flat&logo=twitter&link=https%3A%2F%2Ftwitter.com%2Fachetronic)

> [!IMPORTANT]
> This project is under active development. Some features may change without prior notice.

A lightweight S3 proxy that re-signs requests between your customers and buckets, supporting multiple client authentication methods.


## Motivation

Outbound traffic from S3 buckets is often expensive with many providers. Some providers treat outbound traffic as internal when it goes through alternative points other than the provided S3 endpoint, such as bare-metal machines.

In these situations, a transparent HTTP proxy isn't enough because all S3 client requests are signed at the source, and the signature includes the host. Simply rewriting this header doesn't help—the bucket will see the signature as invalid.

The simplest way to handle this is to intercept the request and re-sign it with valid data. This proxy is exactly the gateway you need.


## Diagram

<img src="https://raw.githubusercontent.com/freepik-company/bifrost/master/docs/img/diagram.png" alt="Bifrost diagram" width="600">


## Flags

As almost every configuration parameter can be defined in environment vars, there are only few flags that can be defined.
They are described in the following table:

| Name              | Description                                          |    Default     | Example                  |
|:------------------|:-----------------------------------------------------|:--------------:|:-------------------------|
| `--log-level`     | Verbosity level for logs                             |     `info`     | `--log-level info`       |
| `--disable-trace` | Disable showing traces in logs                       |     `info`     | `--log-level info`       |
| `--config`        | Path to the configuration file <br> [Config Example] | `bifrost.yaml` | `--bifrost bifrost.yaml` |


> Output is thrown always in JSON as it is more suitable for automations

```console
bifrost run \
    --log-level=info
```


## Configuration

A complete example of the config params can be found in [docs/samples/bifrost.yaml](./docs/samples/bifrost.yaml)


## How to deploy

This project can be deployed in Kubernetes, but also provides binary files
and Docker images to make it easy to be deployed however wanted


### Binaries

Binary files for most popular platforms will be added to the [releases](https://github.com/freepik-company/bifrost/releases)


### Kubernetes

You can deploy `bifrost` in Kubernetes using Helm as follows:

```console
helm repo add bifrost https://freepik-company.github.io/bifrost/

helm upgrade --install --wait bifrost \
  --namespace bifrost \
  --create-namespace freepik-company/bifrost
```

> More information and Helm packages [here](https://freepik-company.github.io/bifrost/)


### Docker

Docker images can be found in GitHub's [packages](https://github.com/freepik-company/bifrost/pkgs/container/bifrost)
related to this repository

> Do you need it in a different container registry? I think this is not needed, but if I'm wrong, please, let's discuss
> it in the best place for that: an issue

## How to contribute

We are open to external collaborations for this project: improvements, bugfixes, whatever.

For doing it, open an issue to discuss the need of the changes, then:

- Fork the repository
- Make your changes to the code
- Open a PR and wait for review

The code will be reviewed and tested (always)

> We are developers and hate bad code. For that reason we ask you the highest quality
> on each line of code to improve this project on each iteration.

## License

Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.




[//]: #

[Config Example]: <./README.md#configuration>
