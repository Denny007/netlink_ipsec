PRO := serv_lis
CFLAGS := -O0 -g3 -Wall

COM_PATH = ../common

EXTRA_CFLAGS := -Dlinux_x64
CFLAGS += $(EXTRA_CFLAGS)
CFLAGS += -I$(COM_PATH)
LDFLAGS = -levent

SRC += main_cm.c
SRC += serv_ipsec.c
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
