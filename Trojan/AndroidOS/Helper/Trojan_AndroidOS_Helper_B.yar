
rule Trojan_AndroidOS_Helper_B{
	meta:
		description = "Trojan:AndroidOS/Helper.B,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {73 70 79 4f 6e 50 68 6f 6e 65 53 74 61 74 65 } //02 00 
		$a_00_1 = {74 72 79 57 61 6b 65 4f 6e 50 61 63 6b 61 67 65 } //02 00 
		$a_00_2 = {75 70 64 61 74 65 50 72 65 69 6e 73 74 61 6c 6c 41 70 6b 49 6e 73 74 61 6c 6c 65 64 52 65 70 6f 72 74 53 74 61 74 75 73 } //00 00 
	condition:
		any of ($a_*)
 
}