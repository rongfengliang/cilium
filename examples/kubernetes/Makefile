include ../../Makefile.defs

ifeq ($(CILIUM_VERSION),)
    CILIUM_VERSION = "$(shell cat ../../VERSION)"
endif

all: transform default.yaml

%.sed:
	for k8s_version in 1.7 1.8 1.9 1.10 1.11; do \
	    mkdir -p $$k8s_version/$(CILIUM_VERSION) && \
	    cd $$k8s_version && \
	    sed -f transforms2sed.sed ../templates/v1/$@ | \
	    sed s+__CILIUM_VERSION__+$(CILIUM_VERSION)+g > "$(CILIUM_VERSION)/$*"; \
	    cd ..; \
	done

%.yaml:
	for k8s_version in 1.7 1.8 1.9 1.10 1.11; do \
	    mkdir -p $$k8s_version/$(CILIUM_VERSION) && \
	    cd $$k8s_version && \
	    cp ../templates/v1/$@ $(CILIUM_VERSION)/$@; \
	    cd ..; \
	done

default.yaml:
	for k8s_version in 1.7 1.8 1.9 1.10 1.11; do \
        cd $$k8s_version/$(CILIUM_VERSION) && \
            rm -f ./$@ && \
            for f in *.yaml; do (cat "$${f}"; echo "---") >> $@; done && \
        cd -; \
	done

clean:
	for k8s_version in 1.7 1.8 1.9 1.10 1.11; do \
        rm -r ./$$k8s_version/$(CILIUM_VERSION); \
	done

transform: cilium-ds.yaml.sed cilium-rbac.yaml.sed cilium-cm.yaml cilium-sa.yaml

.PHONY: transform default.yaml
