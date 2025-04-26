
rule Trojan_BAT_QuasarRAT_K_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 bd a2 3f 09 0f 00 00 00 b8 00 33 00 06 00 00 01 00 00 00 60 00 00 00 28 00 00 00 5c 00 00 00 6f 00 00 00 20 } //2
		$a_01_1 = {77 00 33 00 77 00 70 00 2e 00 65 00 78 00 65 00 } //2 w3wp.exe
		$a_01_2 = {61 00 73 00 70 00 6e 00 65 00 74 00 5f 00 77 00 70 00 2e 00 65 00 78 00 65 00 } //2 aspnet_wp.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}