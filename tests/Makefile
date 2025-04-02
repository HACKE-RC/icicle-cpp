HEADER_ARG = -I../
ICICLE_ARGS_DEBUG = -L../src/target/debug -l:libicicle.a
ICICLE_ARGS_RELEASE = -L../src/target/release -l:libicicle.a
CC_ARGS = -lm
OS := $(shell uname 2>/dev/null || echo Windows)

ifeq ($(OS), Windows)
    RM = del /F /Q
else
    RM = rm -f
endif

tests:
	cc tests.c $(HEADER_ARG) $(ICICLE_ARGS_DEBUG) $(CC_ARGS) -o tests-debug 

tests-release:
	cc tests.c $(HEADER_ARG) $(ICICLE_ARGS_RELEASE) $(CC_ARGS) -o tests-release

all: tests tests-release

run: tests
	./tests-debug

run-release: tests-release
	./tests-release

run-all: tests tests-release
	./tests-debug
	echo "Ran debug mode binary. Now running release mode binary..."
	./tests-release
	echo "Executed both."

clean:
	$(RM) ./tests-debug
	$(RM) ./tests-release
