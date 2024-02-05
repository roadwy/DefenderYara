
rule Trojan_AndroidOS_Stealer_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Stealer.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 74 6d 6c 2f 61 70 70 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //01 00 
		$a_00_1 = {67 65 74 44 65 76 69 63 65 49 6e 66 6f 72 6d 61 74 69 6f 6e } //01 00 
		$a_00_2 = {73 74 61 72 74 48 69 64 65 72 } //01 00 
		$a_00_3 = {64 69 73 61 62 6c 65 49 6e 62 6f 78 53 6d 73 46 69 6c 74 65 72 } //01 00 
		$a_00_4 = {69 6e 73 74 61 6c 6c 41 70 70 } //01 00 
		$a_00_5 = {73 65 6e 64 44 65 6c 61 79 65 64 53 6d 73 } //00 00 
		$a_00_6 = {5d 04 00 } //00 0d 
	condition:
		any of ($a_*)
 
}