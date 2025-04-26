
rule Trojan_BAT_Redline_NEAG_MTB{
	meta:
		description = "Trojan:BAT/Redline.NEAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_01_0 = {06 1e 58 11 05 1f 5d 6f 74 00 00 0a 54 11 05 17 06 1e 58 4a 17 59 6f 75 00 00 0a 25 1f 7a 6f 74 00 00 0a 16 fe 04 16 fe 01 13 06 1f 74 6f 74 00 00 0a 16 fe 04 16 fe 01 13 07 11 05 06 1e 58 4a 17 58 6f 44 00 00 0a 13 05 } //10
		$a_01_1 = {53 6d 61 72 74 41 73 73 65 6d 62 6c 79 2e 48 6f 75 73 65 4f 66 43 61 72 64 73 } //2 SmartAssembly.HouseOfCards
		$a_01_2 = {61 00 73 00 70 00 6e 00 65 00 74 00 5f 00 77 00 70 00 2e 00 65 00 78 00 65 00 } //2 aspnet_wp.exe
		$a_01_3 = {77 00 33 00 77 00 70 00 2e 00 65 00 78 00 65 00 } //2 w3wp.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=16
 
}