
rule Backdoor_Linux_Tsunami_B_MTB{
	meta:
		description = "Backdoor:Linux/Tsunami.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {77 77 77 2e 62 69 6c 6c 79 62 6f 62 62 6f 74 2e 63 6f 6d 2f 63 72 61 77 6c 65 72 } //1 www.billybobbot.com/crawler
		$a_00_1 = {77 77 77 2e 74 68 65 73 75 62 6f 74 2e 64 65 29 } //1 www.thesubot.de)
		$a_00_2 = {2f 64 61 74 61 2f 63 72 6f 6e 74 61 62 2f 72 6f 6f 74 } //1 /data/crontab/root
		$a_00_3 = {63 68 6d 6f 64 20 2b 78 20 2f 73 79 73 74 65 6d 2f 65 74 63 2f 69 6e 69 74 2e 64 2f 63 72 6f 6e 64 } //1 chmod +x /system/etc/init.d/crond
		$a_00_4 = {63 72 65 61 74 69 6e 67 20 63 68 72 6f 6e 74 61 62 20 62 61 63 6b 64 6f 6f 72 } //1 creating chrontab backdoor
		$a_00_5 = {73 65 6e 64 50 61 73 73 77 6f 72 64 45 6d 61 69 6c 26 75 73 65 72 5f 6e 61 6d 65 3d 61 64 6d 69 6e } //1 sendPasswordEmail&user_name=admin
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}