CC:=gcc
GCC:=gcc
RM:=rm
MKDIR:=mkdir

SRCDIR:=src
OBJDIR:=obj

CFLAGS+=-g -Wall -Werror -O2
LFLAGS+=-lcec

libceccat: $(OBJDIR)/libceccat.o
	$(GCC) $(LFLAGS) -o $@ $^

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c -o $@ $^

$(OBJDIR):
	$(MKDIR) -p $@

clean:
	$(RM) -rf $(OBJDIR) libceccat
