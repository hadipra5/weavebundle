FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y cmake ninja-build && rm -rf /var/lib/apt/lists/*

COPY . $SRC/weavebundle
WORKDIR $SRC/weavebundle

COPY oss-fuzz/build.sh $SRC/build.sh
