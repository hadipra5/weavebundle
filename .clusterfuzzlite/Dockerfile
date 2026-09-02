FROM gcr.io/oss-fuzz-base/base-builder:v1
RUN apt-get update && apt-get install -y --no-install-recommends cmake ninja-build \
    && rm -rf /var/lib/apt/lists/*
COPY . $SRC/weavebundle
WORKDIR $SRC/weavebundle
COPY .clusterfuzzlite/build.sh $SRC/build.sh
