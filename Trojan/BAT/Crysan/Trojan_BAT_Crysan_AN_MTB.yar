
rule Trojan_BAT_Crysan_AN_MTB{
	meta:
		description = "Trojan:BAT/Crysan.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 06 00 "
		
	strings :
		$a_03_0 = {25 16 1f 23 9d 6f 6f 90 01 02 0a 25 16 9a 6f 2b 90 01 02 0a 0a 25 17 9a 6f 2b 90 01 02 0a 0b 18 9a 6f 2b 90 01 02 0a 0c 90 0a 3f 00 72 cb 90 01 02 70 6f 6e 90 01 02 0a 17 8d 53 90 01 01 00 01 90 00 } //01 00 
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00 
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //01 00 
		$a_01_3 = {57 65 62 43 6c 69 65 6e 74 } //01 00 
		$a_01_4 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //00 00 
	condition:
		any of ($a_*)
 
}