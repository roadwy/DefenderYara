
rule Trojan_AndroidOS_Gappusin_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Gappusin.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {61 70 70 2e 77 61 70 78 2e 63 6e } //01 00 
		$a_00_1 = {73 6d 73 4d 6f 6e 65 79 } //01 00 
		$a_00_2 = {53 54 41 54 45 5f 46 49 47 48 54 53 4d 53 } //01 00 
		$a_00_3 = {69 73 41 6c 6c 41 74 74 61 63 6b } //01 00 
		$a_00_4 = {61 63 74 69 6f 6e 2f 61 63 63 6f 75 6e 74 2f 73 70 65 6e 64 } //00 00 
	condition:
		any of ($a_*)
 
}