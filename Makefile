IMAGE_NAME=hostlookuper:local
DOCKERFILE=packaging/local-build/Dockerfile

# Hardcoded list of kind clusters that should receive the image
#CLUSTERS = cluster-a cluster-b cluster-c
CLUSTERS = prometheus zurich berne

.PHONY: build kind-load push

## Build the docker image locally
build:
	docker build -f $(DOCKERFILE) -t $(IMAGE_NAME) .

## Load image into each cluster from $(CLUSTERS)
kind-load:
	@for c in $(CLUSTERS); do \
		echo ">>> Loading $(IMAGE_NAME) into kind cluster: $$c"; \
		kind load docker-image $(IMAGE_NAME) --name $$c || exit 1; \
	done

## Build once and load into all clusters
push: build kind-load
	@echo ">>> Image $(IMAGE_NAME) loaded into clusters: $(CLUSTERS)"
