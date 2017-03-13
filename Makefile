build:
	$(MAKE) -s get-submodules
	$(MAKE) -s remove-symlinks
	$(MAKE) -s symlinks
	g++ -std=c++11 -O2 -rdynamic src/bin.cpp -o box
	$(MAKE) -s remove-symlinks

get-submodules:
	git submodule --quiet update --init --remote --recursive

symlinks:
	ln -s ../third_party/autojson/src/lib ./src/json ||
	ln -s ../third_party/cpp-base/src ./src/cpp-base ||
	ln -s ../third_party/cxxopts/include ./src/cxxopts ||

remove-symlinks:
	rm ./src/json ||
	rm ./src/cpp-base ||
	rm ./src/cxxopts ||
