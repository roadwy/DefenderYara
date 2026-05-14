
rule Trojan_BAT_DarkTortilla_RVD_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.RVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_81_0 = {57 9d a2 29 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 1a 01 00 00 57 00 00 00 87 03 00 00 fb 04 00 00 7a 03 00 00 67 03 00 00 c7 00 00 00 b2 07 00 00 01 00 00 00 b8 00 00 00 1f 00 00 00 b5 01 00 00 60 03 00 00 86 00 00 00 01 00 00 00 01 00 00 00 07 00 00 00 03 00 00 00 4a 00 00 00 09 00 00 00 55 } //2
		$a_81_1 = {4b 65 7a 61 64 61 2e 6a 65 79 64 61 73 65 62 61 2e 62 61 74 } //1 Kezada.jeydaseba.bat
		$a_81_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=4
 
}