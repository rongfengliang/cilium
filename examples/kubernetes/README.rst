Kubernetes Deployment
=====================

This directory contains all Cilium deployment files that can be used in
Kubernetes.

Each directory represents a Kubernetes version, from :code:`1.7` to :code:`1.11`,
and inside each version there is a list of directories for each Cilium version
released.

The structure directory will be
:code:`${k8s_major_version}.${k8s_minor_version}/${cilium_major_version}.${cilium_minor_version}`.

To generate those files simply run :code:`make`, which will pick up the Cilium version
from the :code:`VERSION` file at the root of the repo, or if you want to specify
the Cilium version yourself use :code:`make CILIUM_VERSION=X.Y.Z`.

If you want to clean up a specific version, run :code:`make CILIUM_VERSION=X.Y.Z`
which will delete all generated files for a specific Cilium version

Templates
---------

There are templates for each component to be installed in Kubernetes inside
the directory :code:`templates`. The components ending with :code:`.sed` will be
automatically generated based on the template itself and the specific
:code:`transforms2sed.sed` inside each directory for each Kubernetes version.

Files
-----

Inside each :code:`${k8s_major_version}.${k8s_minor_version}/${cilium_major_version}.${cilium_minor_version}`
there are 5 files:

- :code:`cilium-cm.yaml` - The :code:`ConfigMap` and options with some default
  values the user should change

- :code:`cilium-ds.yaml` - The :code:`DaemonSet` to deploy Cilium in the Kubernetes
  cluster, some advanced options can be changed here.

- :code:`cilium-rbac.yaml` - The Cilium's RBAC for the Kubernetes cluster.

- :code:`cilium-sa.yaml` - The Cilium's Kubernetes :code:`ServiceAccount`.

- :code:`default.yaml` - All previous files concatenated into a single file,
  useful to deploy Cilium in a minikube environment with a "single line" command.

Plugins
-------

You can find some plugins to the Kubernetes + Cilium integration inside the
:code:`plugins` directory.