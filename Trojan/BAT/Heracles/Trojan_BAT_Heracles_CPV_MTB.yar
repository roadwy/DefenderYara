
rule Trojan_BAT_Heracles_CPV_MTB{
	meta:
		description = "Trojan:BAT/Heracles.CPV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 72 50 61 41 4d 74 6c 73 63 79 4d 58 4e 33 39 } //01 00 
		$a_01_1 = {4d 46 42 6c 61 6d 35 53 70 65 6b 76 72 } //01 00 
		$a_01_2 = {53 79 73 74 65 6c 78 52 75 6e 74 69 66 65 5f 53 65 72 69 61 6c 69 6e 61 74 69 72 63 74 6c } //01 00 
		$a_01_3 = {61 72 74 64 6f 74 73 69 53 54 4a 55 44 54 } //00 00 
	condition:
		any of ($a_*)
 
}