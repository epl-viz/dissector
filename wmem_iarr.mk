CFLAGS = -std=c89 -Wall -Wextra -g -O0  \
		 `pkg-config --cflags glib-2.0` \
		 -I../..
LDLIBS = `pkg-config --libs glib-2.0`

.DEFAULT: test
test: wmem_iarray.o wmem_iarray_test.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

wmem_iarray.o wmem_iarray_test.o : wmem_iarray.h wmem_iarray_int.h

.PHONY: clean
clean:
	rm -f *.o test

