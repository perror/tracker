# Commands
MAKE=make

# Special rules and targets
.PHONY: all check clean help

# Rules and targets
all:
	@cd src/ && $(MAKE)
	@cp -f src/tracker ./

check: all
	@cp tracker test/
	@cd test/ && $(MAKE)

format:
	clang-format -i -style=file src/*.[ch] include/*.h

tidy:
	clang-tidy src/*.c -config="" -- -std=c11 -Iinclude

clean:
	@cd src/ && $(MAKE) clean
	@cd test/ && $(MAKE) clean
	@rm -f tracker *~ .*~

help:
	@echo "Usage:"
	@echo "  make [all]\t\tBuild all"
	@echo "  make check\t\tRun all the tests"
	@echo "  make format\t\tReformat the code"
	@echo "  make tidy\t\tPerform static-analysis on the code"
	@echo "  make clean\t\tRemove all files generated by make"
	@echo "  make help\t\tDisplay this help"
