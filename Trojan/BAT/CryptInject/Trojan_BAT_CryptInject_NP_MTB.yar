
rule Trojan_BAT_CryptInject_NP_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {6b 2d 73 74 6f 72 61 67 65 2e 63 6f 6d 2f 62 6f 6f 74 73 74 72 61 70 70 65 72 2f 66 69 6c 65 73 2f 6b 72 6e 6c 2e 64 6c 6c } //01 00 
		$a_81_1 = {72 79 6f 73 2e 62 65 73 74 2f 61 70 69 2f 75 70 64 61 74 65 2e 6a 69 74 } //01 00 
		$a_01_2 = {3f b6 1f 09 0b 00 00 00 fa 01 33 00 16 00 00 01 } //01 00 
		$a_01_3 = {39 61 61 35 37 30 30 37 37 30 36 34 } //01 00 
		$a_81_4 = {44 6f 77 6e 6c 6f 61 64 44 4c 4c } //01 00 
		$a_81_5 = {47 65 74 53 63 72 69 70 74 44 61 74 61 } //00 00 
	condition:
		any of ($a_*)
 
}