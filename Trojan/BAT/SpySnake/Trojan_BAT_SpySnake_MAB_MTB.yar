
rule Trojan_BAT_SpySnake_MAB_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 76 65 72 73 65 } //01 00 
		$a_01_1 = {4b 00 7a 00 75 00 65 00 78 00 75 00 6c 00 77 00 68 00 6c 00 66 00 75 00 78 00 65 00 70 00 64 00 } //01 00 
		$a_01_2 = {53 6c 65 65 70 } //01 00 
		$a_01_3 = {45 6e 71 75 65 75 65 } //01 00 
		$a_01_4 = {44 65 71 75 65 75 65 } //01 00 
		$a_01_5 = {73 77 6f 72 68 54 6e 6f 69 74 70 65 63 78 45 6e 6f 4e 70 61 72 57 } //00 00 
	condition:
		any of ($a_*)
 
}