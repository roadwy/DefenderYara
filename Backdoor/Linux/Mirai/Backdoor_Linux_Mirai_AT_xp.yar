
rule Backdoor_Linux_Mirai_AT_xp{
	meta:
		description = "Backdoor:Linux/Mirai.AT!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {67 31 61 62 63 34 64 6d 6f 33 35 68 6e 70 32 6c 69 65 30 6b 6a 66 } //1 g1abc4dmo35hnp2lie0kjf
		$a_01_1 = {47 45 54 20 2f 73 65 74 5f 66 74 70 2e 63 67 69 } //1 GET /set_ftp.cgi
		$a_01_2 = {75 70 6c 6f 61 64 5f 69 6e 74 65 72 76 61 6c 3d 30 } //1 upload_interval=0
		$a_01_3 = {47 45 54 20 2f 66 74 70 74 65 73 74 2e 63 67 69 } //1 GET /ftptest.cgi
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}