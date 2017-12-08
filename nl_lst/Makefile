PRO := lis_xfrm
CFLAGS := -O0 -g3 -Wall

#LIBEVENTPATH=/home/denny/ipsec/libevent-2.1.8-stable
#CFLAGS += -I$(LIBEVENTPATH)/include
#LDFLAGS = -L$(LIBEVENTPATH)/.libs -levent

COM_PATH = ../common
EXTRA_CFLAGS := -Dlinux_x64

CFLAGS += -I$(COM_PATH)
CFLAGS += $(EXTRA_CFLAGS)

LDFLAGS = -levent

SRC += main.c
SRC += nl_con.c
SRC += nl_xfrm.c
SRC += nl_parse.c
SRC += nl_sa.c
SRC += nl_sp.c
SRC += nl_msg.c
SRC += $(COM_PATH)/plog.c
SRC += $(COM_PATH)/logger.c
SRC += $(COM_PATH)/sockmisc.c

OBJ_SRC = $(patsubst %.c,%.o,$(SRC))

.PHONY:all
all:$(PRO)


$(PRO):$(OBJ_SRC)
	$(CC) -o $@  $^ $(LDFLAGS)

$(OBJ_SRC):%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY:clean
clean:
	rm -rf *.o $(PRO)
