#
# Container to build Linux SEAL libraries, python wrapper, and examples
#
FROM ubuntu:18.04
MAINTAINER Todd Stavish <toddstavish@gmail.com>
RUN echo hello
RUN apt-get update
# Install binary dependencies
RUN apt-get -qqy update && apt-get install -qqy \
	g++ \
	git \
	make \
	python3 \
	python3-dev \
	python3-pip \
	sudo \
        libdpkg-perl \
	--no-install-recommends

# Build SEAL libraries
RUN mkdir -p SEAL/
COPY /SEAL/ /SEAL/SEAL/
WORKDIR /SEAL/SEAL/
RUN chmod +x configure
RUN sed -i -e 's/\r$//' configure
RUN ./configure
RUN make
ENV LD_LIBRARY_PATH SEAL/bin:$LD_LIBRARY_PATH

# Build SEAL C++ example
COPY /SEALExamples /SEAL/SEALExamples
WORKDIR /SEAL/SEALExamples
RUN make

# Build SEAL Python wrapper
COPY /SEALPython /SEAL/SEALPython
COPY /SEALPythonExamples /SEAL/SEALPythonExamples

WORKDIR /SEAL/SEALPython
RUN pip3 install --upgrade pip
RUN pip3 install setuptools
RUN pip3 install -r requirements.txt
RUN pip3 install --no-cache-dir numpy scipy pandas matplotlib jupyter sklearn
RUN git clone https://github.com/pybind/pybind11.git
WORKDIR /SEAL/SEALPython/pybind11
RUN git checkout a303c6fc479662fd53eaa8990dbc65b7de9b7deb
WORKDIR /SEAL/SEALPython
RUN python3 setup.py build_ext -i

RUN git clone https://github.com/n1analytics/python-paillier.git
WORKDIR /SEAL/SEALPython/python-paillier
RUN python3 setup.py install

ENV PYTHONPATH $PYTHONPATH:/SEAL/SEALPython:/SEAL/bin

# Return to SEAL root directory
WORKDIR /SEAL
EXPOSE 8080
# Clean-up
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
WORKDIR /src/app
CMD python3 main.py
