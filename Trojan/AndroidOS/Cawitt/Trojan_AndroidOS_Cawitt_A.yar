
rule Trojan_AndroidOS_Cawitt_A{
	meta:
		description = "Trojan:AndroidOS/Cawitt.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 63 61 72 62 6f 6e 74 65 74 72 61 69 6f 64 69 64 65 } //01 00 
		$a_01_1 = {6f 72 69 6b 61 } //01 00 
		$a_01_2 = {7b 61 63 63 69 64 65 6e 74 61 6c 79 7d } //01 00 
		$a_01_3 = {7b 74 72 6f 6c 6c 7d } //01 00 
		$a_01_4 = {2e 71 69 70 69 6d 2e 72 75 } //00 00 
	condition:
		any of ($a_*)
 
}