
rule Trojan_AndroidOS_Stealer_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Stealer.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 73 2f 73 2f 41 6c 72 6d 52 63 3b } //01 00 
		$a_01_1 = {4c 73 2f 73 2f 53 52 63 3b } //01 00 
		$a_01_2 = {64 69 73 61 62 6c 65 49 6e 62 6f 78 53 6d 73 46 69 6c 74 65 72 } //01 00 
		$a_01_3 = {69 6e 73 74 61 6c 6c 41 70 70 } //01 00 
		$a_01_4 = {73 74 61 72 74 48 69 64 65 72 } //01 00 
		$a_01_5 = {67 65 74 44 65 76 69 63 65 49 6e 66 6f 72 6d 61 74 69 6f 6e } //00 00 
		$a_00_6 = {5d 04 00 00 51 } //ff 03 
	condition:
		any of ($a_*)
 
}