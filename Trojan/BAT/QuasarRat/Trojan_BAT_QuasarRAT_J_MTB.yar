
rule Trojan_BAT_QuasarRAT_J_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 bd a2 3f 09 0b 00 00 00 b8 00 33 00 02 00 00 01 00 00 00 69 00 00 00 4e 00 00 00 9c 00 00 00 ca } //2
		$a_01_1 = {77 00 33 00 77 00 70 00 2e 00 65 00 78 00 65 00 } //2 w3wp.exe
		$a_01_2 = {61 00 73 00 70 00 6e 00 65 00 74 00 5f 00 77 00 70 00 2e 00 65 00 78 00 65 00 } //2 aspnet_wp.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}