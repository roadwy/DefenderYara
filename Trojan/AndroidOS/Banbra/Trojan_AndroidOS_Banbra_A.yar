
rule Trojan_AndroidOS_Banbra_A{
	meta:
		description = "Trojan:AndroidOS/Banbra.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 6d 79 64 6f 63 73 2f 64 6f 63 75 6d 65 6e 74 73 2f 53 65 72 76 69 63 65 73 2f 73 65 72 76 69 63 65 4d 61 67 69 63 3b } //02 00 
		$a_01_1 = {53 65 72 76 69 63 65 73 2f 73 65 72 76 69 63 65 43 6f 6e 63 6c 75 64 65 3b } //02 00 
		$a_01_2 = {61 63 74 69 6f 6e 3d 63 68 65 63 6b 41 50 26 64 61 74 61 3d } //00 00 
	condition:
		any of ($a_*)
 
}