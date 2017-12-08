all:
	make -C lst_cm/
	make -C nl_lst/

help:  
	@echo "===============A common Makefilefor c programs=============="  
	@echo "Copyright (C) 2014 liuy0711 \at 163\dot com"  
	@echo "The following targets aresupport:"  
	@echo  
	@echo " all              - (==make) compile and link"  
	@echo " obj              - just compile, withoutlink"  
	@echo " clean            - clean target"  
	@echo " distclean        - clean target and otherinformation"  
	@echo " tags             - create ctags for vimeditor"  
	@echo " help             - print help information"  
	@echo  
	@echo "To make a target, do 'make[target]'"  
	@echo "========================= Version2.0 =======================" 

clean :  
	$(MAKE) -C lst_cm clean  
	$(MAKE) -C nl_lst clean  



.PHONY : all clean help  
