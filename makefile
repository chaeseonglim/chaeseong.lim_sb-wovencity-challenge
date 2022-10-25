CC=gcc
CFLAGS=-Wall -Wreturn-type -Wdeprecated-declarations -DDEBUG
RUN_FOLDER=unit_test
SAMPLE_FOLDER=samples
SAMPLE_NAME=test
SCRIPT_FOLDER=scripts
BUILDDIR=build
SRCDIR=src
#TODO support multiple samples
SAMPLE_TEST=$(SAMPLE_FOLDER)/$(SAMPLE_NAME)1
SAMPLE_SIGNED=$(RUN_FOLDER)/$(SAMPLE_NAME)_signed

SRC=$(wildcard $(SRCDIR)/*.c)
OBJ=$(patsubst $(SRCDIR)/%.c, $(BUILDDIR)/%.o, $(SRC))

# check dependencies (openssl, python3, openssl-dev,...)
#   -  test_sign_keypair checks for openssl
# check if CPPFLAGS and LDFLAGS are defined.
# otherwise raise an error
#
# check_dependencies:

# install create the build folder and unit test folder
install: 
	@mkdir -p $(RUN_FOLDER)
	@mkdir -p $(BUILDDIR)

gen_sample_bin: $(SAMPLE_TEST) 

# to Generate the samples images
$(SAMPLE_TEST).o: $(SAMPLE_TEST).c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -c $< -o $(SAMPLE_TEST).o

$(SAMPLE_TEST): $(SAMPLE_TEST).o
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $(SAMPLE_TEST) $<

# sign the sample image
build_sign_sample_image:
	python3 $(SCRIPT_FOLDER)/image.py $(RUN_FOLDER) $(SAMPLE_TEST)

# test that new generated keys works well with openssl
test_sign_keypair:
	$(SCRIPT_FOLDER)/verify_keypair.sh $(RUN_FOLDER) || (echo "verify_keypair failed $$?"; exit 1)

$(BUILDDIR)/test: $(OBJ)
	$(CC) -o $(BUILDDIR)/test $(OBJ) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -lssl -lcrypto -v

$(BUILDDIR)/%.o: $(SRCDIR)/%.c
	$(CC)  -lssl -lcrypto -c $< -o $@ $(CPPFLAGS) $(CFLAGS) $(LDFLAGS)

build_secureboot_app: $(BUILDDIR)/test

.PHONY: clean 

all: clean install gen_sample_bin build_sign_sample_image test_sign_keypair build_secureboot_app
	ln -s $(BUILDDIR)/test test
	./test $(SAMPLE_SIGNED)

clean:
	rm -rf $(RUN_FOLDER)
	rm -rf $(BUILDDIR)
	rm -f test *.o $(SAMPLE_FOLDER)/*.o