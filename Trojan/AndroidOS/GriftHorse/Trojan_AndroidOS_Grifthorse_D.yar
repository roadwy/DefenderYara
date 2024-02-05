
rule Trojan_AndroidOS_Grifthorse_D{
	meta:
		description = "Trojan:AndroidOS/Grifthorse.D,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 6f 5f 6c 61 6e 67 5f 62 67 } //01 00 
		$a_01_1 = {74 65 78 74 76 69 65 77 6f 54 65 78 74 } //01 00 
		$a_01_2 = {69 20 73 70 65 61 6b 20 73 6f 6d 65 74 68 69 6e 67 } //01 00 
		$a_01_3 = {74 72 61 73 66 61 63 74 69 76 69 74 79 5f 77 65 62 76 69 65 77 } //00 00 
	condition:
		any of ($a_*)
 
}