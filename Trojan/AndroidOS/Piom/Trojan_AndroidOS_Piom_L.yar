
rule Trojan_AndroidOS_Piom_L{
	meta:
		description = "Trojan:AndroidOS/Piom.L,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {67 65 74 70 61 64 65 73 74 61 74 75 73 } //02 00 
		$a_01_1 = {70 61 64 65 74 72 61 63 2e 63 6f 6d 2f 61 70 69 2f } //02 00 
		$a_01_2 = {75 70 64 61 74 65 73 74 61 74 75 73 70 61 64 65 } //00 00 
	condition:
		any of ($a_*)
 
}