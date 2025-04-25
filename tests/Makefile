HEADER_ARG = -I../
ICICLE_ARGS_DEBUG = -L../src/target/debug -l:libicicle.a -lkeystone
ICICLE_ARGS_RELEASE = -L../src/target/release -l:libicicle.a
CC_ARGS = -lm
OS := $(shell uname 2>/dev/null || echo Windows)

ifeq ($(OS), Windows)
    RM = del /F /Q
else
    RM = rm -f
endif

tests:
	# g++ mapping_test.cpp $(HEADER_ARG) $(ICICLE_ARGS_DEBUG) $(CC_ARGS) -o mapping-test-debug
	cc tests.c $(HEADER_ARG) $(ICICLE_ARGS_DEBUG) $(CC_ARGS) -o tests-debug
	# cc debug_features.c $(HEADER_ARG) $(ICICLE_ARGS_DEBUG) $(CC_ARGS) -o features-debug
	# cc hook_tests.c $(HEADER_ARG) $(ICICLE_ARGS_DEBUG) $(CC_ARGS) -o hook-tests-debug
	# cc snapshot_tests.c $(HEADER_ARG) $(ICICLE_ARGS_DEBUG) $(CC_ARGS) -o snapshot-tests-debug
# 	g++ archs.cpp $(HEADER_ARG) $(ICICLE_ARGS_DEBUG) $(CC_ARGS) -o archs-tests-debug

tests-release:
	cc tests.c $(HEADER_ARG) $(ICICLE_ARGS_RELEASE) $(CC_ARGS) -o tests-release
	cc hook_tests.c $(HEADER_ARG) $(ICICLE_ARGS_RELEASE) $(CC_ARGS) -o hook-tests-release
	cc snapshot_tests.c $(HEADER_ARG) $(ICICLE_ARGS_RELEASE) $(CC_ARGS) -o snapshot-tests-release

all: tests tests-release

run: tests
	./tests-debug
	./hook-tests-debug
	./snapshot-tests-debug

run-release: tests-release
	./tests-release
	./hook-tests-release
	./snapshot-tests-release

run-all: tests tests-release
	./tests-debug
	./hook-tests-debug
	./snapshot-tests-debug
	echo "Ran debug mode binary. Now running release mode binary..."
	./tests-release
	./hook-tests-release
	./snapshot-tests-release
	echo "Executed both."

clean:
	$(RM) ./tests-debug
	$(RM) ./hook-tests-debug
	$(RM) ./snapshot-tests-debug
	$(RM) ./features-debug
	$(RM) ./tests-release
	$(RM) ./hook-tests-release
	$(RM) ./snapshot-tests-release
