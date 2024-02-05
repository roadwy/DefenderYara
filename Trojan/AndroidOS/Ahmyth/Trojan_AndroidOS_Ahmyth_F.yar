
rule Trojan_AndroidOS_Ahmyth_F{
	meta:
		description = "Trojan:AndroidOS/Ahmyth.F,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {61 68 6d 79 74 68 2f 49 4f 53 6f 63 6b 65 74 3b } //02 00 
		$a_01_1 = {66 69 6e 64 43 61 6d 65 72 61 4c 69 73 74 } //02 00 
		$a_01_2 = {61 68 6d 79 74 68 2f 43 61 6c 6c 73 4d 61 6e 61 67 65 72 3b } //02 00 
		$a_01_3 = {78 30 30 30 30 6d 63 } //00 00 
	condition:
		any of ($a_*)
 
}