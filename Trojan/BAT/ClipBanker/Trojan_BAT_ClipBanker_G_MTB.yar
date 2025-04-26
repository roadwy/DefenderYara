
rule Trojan_BAT_ClipBanker_G_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {77 00 51 00 51 00 53 00 78 00 4a 00 66 00 64 00 4c 00 2e 00 62 00 69 00 6e 00 } //1 wQQSxJfdL.bin
		$a_01_1 = {61 00 53 00 49 00 4c 00 6c 00 7a 00 43 00 77 00 58 00 42 00 53 00 72 00 51 00 } //1 aSILlzCwXBSrQ
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 65 00 6e 00 73 00 61 00 6a 00 61 00 79 00 2e 00 63 00 6f 00 6d 00 2f 00 67 00 65 00 74 00 53 00 65 00 6d 00 65 00 73 00 74 00 65 00 72 00 73 00 2e 00 70 00 68 00 70 00 } //1 http://mensajay.com/getSemesters.php
		$a_81_3 = {61 64 64 5f 53 68 75 74 64 6f 77 6e } //1 add_Shutdown
		$a_81_4 = {44 6f 63 35 32 } //1 Doc52
		$a_81_5 = {57 69 6e 64 6f 77 73 31 36 } //1 Windows16
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}