FROM itsafeaturemythic/mythic_python_base:latest

# Install build tools needed to build the donut native library (cross-compile for Windows)
RUN apt-get clean && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        mingw-w64 \
        python3 \
        python3-pip \
        python3-venv \
        git \
        && \
    rm -rf /var/lib/apt/lists/*

RUN pip install build

# Copy the project files into the container
COPY . /Mythic

# If donut directory doesn't exist locally, clone it from GitHub
RUN if [ ! -d /Mythic/agent_code/donut ]; then git clone https://github.com/TheWover/donut.git /Mythic/agent_code/donut; fi

# Build the native donut library (uses the Makefile under agent_code/donut)
WORKDIR /Mythic/agent_code/donut
RUN make -f Makefile.mingw
RUN python -m build
RUN pip install dist/donut*.whl

WORKDIR /Mythic
RUN pip install -r requirements.txt


CMD ["python3", "main.py"]