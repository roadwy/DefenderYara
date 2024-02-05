
rule Trojan_AndroidOS_SpyNote_B{
	meta:
		description = "Trojan:AndroidOS/SpyNote.B,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {56 48 68 72 65 76 57 76 65 72 } //01 00 
		$a_00_1 = {42 54 52 65 72 76 71 65 } //01 00 
		$a_00_2 = {4c 73 70 6c 61 73 68 2f 70 6c 61 79 67 6f } //00 00 
	condition:
		any of ($a_*)
 
}