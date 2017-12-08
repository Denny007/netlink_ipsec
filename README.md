功能：1、nl_lst程序监听netlink组播消息，从而获取linux内核中IPsec相关信息，包括SAD、SPD
      2、nl_lst通过unix域套接字将SAD和SPD同步给lst_serv
      3、使用到的第三方库为libevent

代码结构：
	common:
		nl_lst和lst_serv双方共同使用到的函数，sockmisc.c处理基本socket，plog.c和logger.c是打印日志和调试信息
	nl_lst:
		监听netlink组播消息，获取SAD和SPD传给lst_serv
	lst_serv
		监听nl_lst传过来的消息，然后写入共享内存中
