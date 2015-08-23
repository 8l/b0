## Requires GNU Make (aka gmake on *BSD)

CC=gcc
AS=fasm
B0=../../b0
CFLAGS=-Wall -m64 -L/usr/lib/64
LDFLAGS=
B0FLAGS=-W

GTK2_CFLAGS=`pkg-config --cflags gtk+-2.0`
GTK2_LIBS=`pkg-config --libs gtk+-2.0`

GLADE3_CFLAGS=`pkg-config --cflags libglade-2.0`
GLADE3_LIBS=`pkg-config --libs libglade-2.0` 

GNOME_CFLAGS=`pkg-config --cflags libgnomeui-2.0 libgnome-2.0`
GNOME_LIBS=`pkg-config --libs libgnomeui-2.0 libgnome-2.0`

OBJECTS = gtk_glade

all: $(OBJECTS)

clean:
	rm -f *.asm *.o *~ core $(OBJECTS)

gtk_glade: gtk_glade.o gnome3.glade
	$(CC) $(CFLAGS) $(GTK2_CFLAGS) $(GTK2_LIBS) $(GLADE3_CFLAGS) $(GLADE3_LIBS)  -o $@ $<

.SUFFIXES: .o .asm .b0

.asm.o:
	$(AS) $< $@
	
.b0.asm:
	$(B0) $(B0FLAGS) -o$@ $<
