
rule Backdoor_Linux_Mirai_GQ_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.GQ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_02_0 = {2f 62 69 6e 2f 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-10] 2e ?? ?? ?? 2f 62 69 6e 73 2e 73 68 3b 20 63 68 6d 6f 64 20 2b 78 20 62 69 6e 73 2e 73 68 3b 20 73 68 20 62 69 6e 73 2e 73 68 3b 20 2f 62 69 6e 2f 63 75 72 6c 20 2d 6b 20 2d 4c 20 2d 2d 6f 75 74 70 75 74 20 62 69 6e 73 2e 73 68 20 68 74 74 70 3a 2f 2f [0-10] 2e ?? ?? ?? 2f 62 69 6e 73 2e 73 68 3b 20 63 68 6d 6f 64 20 2b 78 20 62 69 6e 73 2e 73 68 } //1
		$a_01_1 = {2f 62 69 6e 2f 73 79 73 74 65 6d 63 74 6c 20 65 6e 61 62 6c 65 20 62 6f 74 } //1 /bin/systemctl enable bot
		$a_01_2 = {2f 6c 69 62 2f 73 79 73 74 65 6d 64 2f 73 79 73 74 65 6d 2f 62 6f 74 2e 73 65 72 76 69 63 65 } //1 /lib/systemd/system/bot.service
		$a_01_3 = {2f 65 74 63 2f 69 6e 69 74 2f 62 6f 74 2e 63 6f 6e 66 } //1 /etc/init/bot.conf
		$a_01_4 = {2f 73 62 69 6e 2f 69 6e 69 74 63 74 6c 20 73 74 61 72 74 20 62 6f 74 } //1 /sbin/initctl start bot
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}