
rule Trojan_BAT_CobaltStrike_ST_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 31 34 34 2e 34 38 2e 32 34 30 2e 38 35 2f 31 38 2e 65 78 65 } //1 http://144.48.240.85/18.exe
		$a_81_1 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
		$a_81_2 = {67 65 74 5f 50 61 73 73 77 6f 72 64 } //1 get_Password
		$a_81_3 = {73 65 74 5f 50 61 73 73 77 6f 72 64 } //1 set_Password
		$a_81_4 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_81_5 = {53 65 65 64 44 61 74 61 } //1 SeedData
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}