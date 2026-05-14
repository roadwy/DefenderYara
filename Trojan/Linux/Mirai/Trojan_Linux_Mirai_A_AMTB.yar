
rule Trojan_Linux_Mirai_A_AMTB{
	meta:
		description = "Trojan:Linux/Mirai.A!AMTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {24 28 6c 73 20 2d 6c 20 22 24 70 69 64 2f 65 78 65 22 29 22 20 69 6e 20 2a 22 28 64 65 6c 65 74 65 64 29 22 2a 7c 2a 22 2f 2e 22 2a 29 20 6b 69 6c 6c 20 2d 39 20 22 24 7b 70 69 64 23 23 2a 2f 7d } //$(ls -l "$pid/exe")" in *"(deleted)"*|*"/."*) kill -9 "${pid##*/}  1
		$a_80_1 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 77 67 65 74 20 68 74 74 70 3a 2f 2f } ///bin/busybox wget http://  1
		$a_80_2 = {2f 77 67 65 74 2e 73 68 20 2d 4f 20 2d 3e 20 77 67 65 74 3b 63 68 6d 6f 64 20 37 37 37 20 77 67 65 74 3b 2e 2f 77 67 65 74 } ///wget.sh -O -> wget;chmod 777 wget;./wget  1
		$a_80_3 = {74 66 74 70 2e 73 68 20 2d 6c 20 2d 3e 20 74 66 74 70 3b 63 68 6d 6f 64 20 37 37 37 20 74 66 74 70 3b 2e 2f 74 66 74 70 } //tftp.sh -l -> tftp;chmod 777 tftp;./tftp  1
		$a_80_4 = {63 75 72 6c 20 68 74 74 70 3a 2f 2f } //curl http://  1
		$a_80_5 = {2f 63 75 72 6c 2e 73 68 20 2d 6f 20 2d 3e 20 63 75 72 6c 3b 63 68 6d 6f 64 20 37 37 37 20 63 75 72 6c 3b 2e 2f 63 75 72 6c } ///curl.sh -o -> curl;chmod 777 curl;./curl  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}