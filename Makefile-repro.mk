all:
	echo "Helper Makefile for build reproduction test, done on Fedora 30 and Ubuntu 18.04, with system and bundled hidapi"
	echo "(4 configurations total). Dependencies are taken from the Heads project."
	echo "Run 'repro-build' target to build Docker images, and 'repro-run' to run reproduction test."

.PHONY: repro-build repro-run repro-build-fedora repro-build-ubuntu

repro-build: | repro-build-ubuntu repro-build-fedora

repro-build-fedora:
	sudo docker build -f Dockerfile.fedora . -t nhv-f

repro-build-ubuntu:
	sudo docker build -f Dockerfile.ubuntu . -t nhv-u

# BUILDCMD=cmake -DUSE_SYSTEM_HIDAPI=OFF # failing (for tests)
BUILDCMD=cmake -DCMAKE_C_FLAGS=-fdebug-prefix-map=$(PWD)=heads -gno-record-gcc-switches -DADD_GIT_INFO=OFF -DCMAKE_BUILD_TYPE=Release ..
BUILD1=$(BUILDCMD) -DUSE_SYSTEM_HIDAPI=ON
BUILD2=$(BUILDCMD) -DUSE_SYSTEM_HIDAPI=OFF
#USERNS=bash -c "echo 1 > /proc/sys/kernel/unprivileged_userns_clone" &&
REPROTEST=env PYTHONIOENCODING=utf-8 reprotest --min-cpus 2
BINARY=build/hotp_verification
BEXEC=make clean && make
CMD1=$(USERNS) $(REPROTEST) "cd build && $(BUILD1) && $(BEXEC)"
CMD2=$(USERNS) $(REPROTEST) "cd build && $(BUILD2) && $(BEXEC)"
TEE=| tee -a log.txt
repro-run:
	mkdir -p build
	rm -rf ./build/*
	echo > log.txt
	sudo docker run -it --privileged  -v $(PWD):/app nhv-u $(CMD1) $(BINARY) $(TEE)
	sudo docker run -it --privileged  -v $(PWD):/app nhv-u $(CMD2) $(BINARY) $(TEE)
	sudo docker run -it --privileged  -v $(PWD):/app nhv-f $(CMD1) $(BINARY) $(TEE)
	sudo docker run -it --privileged  -v $(PWD):/app nhv-f $(CMD2) $(BINARY) $(TEE)
	@echo finished with success
	grep "./build/hotp_verification"  log.txt | sort -u
