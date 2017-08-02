build:
	$(MAKE) -s get-submodules
	$(MAKE) -s remove-symlinks
	$(MAKE) -s symlinks
	g++ -std=c++11 -O2 -rdynamic src/bin.cpp -o box
	$(MAKE) -s remove-symlinks

get-submodules:
	git submodule --quiet update --init --recursive

symlinks:
	ln -s ../third_party/autojson/src/lib ./src/json || true
	ln -s ../third_party/cpp-base/src ./src/cpp-base || true
	ln -s ../third_party/cxxopts/include ./src/cxxopts || true

remove-symlinks:
	rm ./src/json || true
	rm ./src/cpp-base || true
	rm ./src/cxxopts || true
