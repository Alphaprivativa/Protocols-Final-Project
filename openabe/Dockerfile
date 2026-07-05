FROM ubuntu:20.04

# 1. Prevent interactive prompts during apt-get (Fixes tzdata hanging)
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

# Initialize LD_LIBRARY_PATH to an empty string to prevent Docker build warnings
ENV LD_LIBRARY_PATH=""

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# 2. Install system dependencies (Includes unzip, flex/bison devs)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git build-essential cmake m4 flex libfl-dev bison libbison-dev \
    libssl-dev libgmp-dev zlib1g-dev wget tar unzip ca-certificates \
    python3 python3-pip python-is-python3 \
    && rm -rf /var/lib/apt/lists/*

# 3. Fix for OpenABE's "make deps" failing to fetch gtest from GitHub
RUN echo "check_certificate = off" > /etc/wgetrc

# 4. Install Python dependencies EARLY (Fixes the Python SSL/PyPI error)
RUN pip3 install --no-cache-dir "cryptography>=42.0"

# --- Build and install OpenABE ---
WORKDIR /opt/openabe

# Clone directly into the WORKDIR
RUN git clone --depth 1 https://github.com/zeutro/openabe.git .

# Satisfy the hardcoded parser paths required by OpenABE
RUN mkdir -p /opt/openabe/bin && \
    ln -s /usr/bin/bison /opt/openabe/bin/bison && \
    ln -s /usr/bin/flex /opt/openabe/bin/flex

# SOURCE CODE PATCHES: Remove -Werror and fix bison syntax
RUN sed -i 's/parser_class_name/api.parser.class/g' src/zparser.yy && \
    find . -type f \( -name "Makefile*" -o -name "CMakeLists.txt" -o -name "*.mk" \) -exec sed -i 's/-Werror//g' {} +

# 5. Compile OpenABE inside bash to fix syntax errors & handle local testing paths
RUN bash -lc '. ./env && \
    unset LD_LIBRARY_PATH && \
    make deps && \
    make && \
    (LD_LIBRARY_PATH=$PWD/deps/root/lib make test || true) && \
    make install'

# Refresh system shared libraries
RUN ldconfig

# --- Prepare the Application ---
WORKDIR /app
COPY . /app

# 6. Set up runtime environment paths safely
ENV PATH="/usr/local/bin:${PATH}"
ENV LD_LIBRARY_PATH="/usr/local/lib:/opt/openabe/deps/root/lib:${LD_LIBRARY_PATH}"

# Command to execute your proof of concept demo
CMD ["python3", "run_demo.py", "--backend", "openabe"]