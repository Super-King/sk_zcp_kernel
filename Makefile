all:
	make -C driver
	make -C lib
	make -C example
clean:
	make -C example clean
	make -C lib clean
	make -C driver clean
