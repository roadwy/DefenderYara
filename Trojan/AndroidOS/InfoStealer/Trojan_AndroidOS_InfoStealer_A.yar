
rule Trojan_AndroidOS_InfoStealer_A{
	meta:
		description = "Trojan:AndroidOS/InfoStealer.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 6f 6e 6e 65 63 74 69 6f 6e 4d 61 6e 61 67 65 72 24 31 30 30 30 30 30 30 30 31 3b } //01 00 
		$a_00_1 = {43 6f 6e 6e 65 63 74 69 6f 6e 4d 61 6e 61 67 65 72 24 31 30 30 30 30 30 30 30 30 3b } //01 00 
		$a_00_2 = {67 65 74 43 61 6c 6c 73 4c 6f 67 73 } //01 00 
		$a_00_3 = {73 74 61 72 74 52 65 63 6f 72 64 69 6e 67 } //01 00 
		$a_00_4 = {73 65 6e 64 50 68 6f 74 6f } //01 00 
		$a_00_5 = {73 65 6e 64 56 6f 69 63 65 } //00 00 
		$a_00_6 = {5d 04 00 00 } //3d f3 
	condition:
		any of ($a_*)
 
}