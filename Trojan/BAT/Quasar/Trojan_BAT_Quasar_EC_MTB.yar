
rule Trojan_BAT_Quasar_EC_MTB{
	meta:
		description = "Trojan:BAT/Quasar.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 6b 7a 6a 7a 77 6f 61 69 78 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //01 00 
		$a_01_1 = {52 65 73 6f 75 72 63 65 44 69 63 74 69 6f 6e 61 72 79 4c 6f 63 61 74 69 6f 6e } //01 00 
		$a_01_2 = {52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } //01 00 
		$a_01_3 = {53 79 73 74 65 6d 2e 52 65 73 6f 75 72 63 65 73 } //01 00 
		$a_01_4 = {63 78 6e 62 76 72 73 6d 72 6c } //01 00 
		$a_01_5 = {76 72 69 75 73 62 77 76 79 64 } //00 00 
	condition:
		any of ($a_*)
 
}