meltdown: meltdown.cpp Makefile
	$(CXX) $< -std=c++14 -Wall -O2 -mrtm -o $@

clean:
	rm -f meltdown
	
.PHONY: clean
