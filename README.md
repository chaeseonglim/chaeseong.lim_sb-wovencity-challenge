# Introduction
This is a secure boot proof of concept which is going to be used as a challenge for new candidates.

The challenge is described **[link](https://docs.google.com/document/d/1eLC2lU1nXPM4MPzaPCbX5O9jPEZ7BgO4auIGpP58d78/edit#)**.

This git repository is structured in:
* **samples** folder  that contains the source code of the sample application, called test1.c, that will be signed by the Certificate Authority. Note the makefile compiles the sample images. At the time being, the sample app is a classical hello world.
* **scripts** folder that contains a python script that instruments the signature process and generation of key pairs. Make sure to install the requirements for using the script. More details in the [INSTALL.md](INSTALL.md).
* **src** folder that contains a runnable implementation of a secure boot in C based on openssl-devel. Make sure to have the openssl development library installed on your workstation. More details in the [INSTALL.md](INSTALL.md).
* There are two extra temporary folders (**build** and **unit_test**) that are created as a consequence of the building and running process. 

## Build
The makefile is self-explanatory but following the main targets:
* *install*, it creates the necessary folders used by the source code.
* *gen_sample_bin*, it goes to the **samples** folder and compile the sample.
* *build_sign_sample_image*, it signs the sample using a new generated RSA keypair. If you would like to keep the same RSA keypair, do not use the *clean* target.
* *test_sign_keypair*, it tests the RSA keypair
* *build_secureboot_app*, it compiles and links the secure boot's source code and generates a test executable in the root repository folder.
* *clean*, it cleans the temporary folders and files
* *all*, instruments all in one.

The openssl library is used by the secure boot code. Thus, in order to build the source code, it is convenient to define the following global variables:
LDFLAGS=-L\<path to openssl lib folder\> 
CPPFLAGS=-I\<path to openssl include folder\>
PKG_CONFIG_PATH=\<path to openssl lib pkgconfig\> (relevant for OSX)

## Usage
An executable called *test* is created in the root repository folder used to verify the signed images. 

Execute it using `./test` and the outcome of the execution will be

![Secure boot outcome](outcome.png)

### Docker image
A docker container is also created to facilite the portability. Use the following sequence to execute the app:
1. `docker build -t="ikanekb/openssl" .`
2. `docker run --rm -it  --name openssl ikanekb/openssl`
