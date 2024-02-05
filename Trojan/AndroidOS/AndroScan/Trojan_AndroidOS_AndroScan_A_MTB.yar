
rule Trojan_AndroidOS_AndroScan_A_MTB{
	meta:
		description = "Trojan:AndroidOS/AndroScan.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 6e 64 72 6f 73 63 61 6e 2e 6e 65 74 2f 69 6e 73 74 61 6c 6c 2e 70 68 70 } //01 00 
		$a_00_1 = {6d 65 73 73 61 67 65 20 74 6f 20 61 6c 6c 20 6f 66 20 74 68 65 20 64 65 76 69 63 65 e2 80 99 73 20 63 6f 6e 74 61 63 74 73 } //01 00 
		$a_00_2 = {73 70 79 20 6f 6e 20 74 68 65 20 53 4d 53 } //01 00 
		$a_00_3 = {4d 41 4c 57 41 52 45 53 44 42 } //01 00 
		$a_00_4 = {53 4d 53 20 74 72 6f 6a 61 6e } //01 00 
		$a_00_5 = {73 65 6e 64 20 53 4d 53 20 6d 65 73 73 61 67 65 73 } //00 00 
		$a_00_6 = {5d 04 00 00 54 } //ba 04 
	condition:
		any of ($a_*)
 
}