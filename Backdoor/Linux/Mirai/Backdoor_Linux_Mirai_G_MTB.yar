
rule Backdoor_Linux_Mirai_G_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.G!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 74 66 74 70 20 2d 72 20 62 6f 74 2e 25 73 } //2 /bin/busybox tftp -r bot.%s
		$a_00_1 = {63 68 6d 6f 64 20 37 37 37 20 2e 74 3b 20 2e 2f 2e 74 20 74 65 6c 6e 65 74 2e } //2 chmod 777 .t; ./.t telnet.
		$a_00_2 = {47 45 54 20 2f 62 6f 74 2e } //1 GET /bot.
		$a_00_3 = {25 64 2e 25 64 2e 25 64 2e 25 64 2f 62 6f 74 2e 25 73 20 2d 4f } //1 %d.%d.%d.%d/bot.%s -O
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}