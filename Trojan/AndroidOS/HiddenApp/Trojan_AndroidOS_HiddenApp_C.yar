
rule Trojan_AndroidOS_HiddenApp_C{
	meta:
		description = "Trojan:AndroidOS/HiddenApp.C,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 61 6d 2f 78 74 72 61 63 6b 2f 4c 6f 6c 61 41 63 74 69 76 69 74 79 } //01 00 
		$a_00_1 = {78 74 72 61 63 6b 2e 49 4e 54 45 4e 54 5f 53 48 4f 57 } //01 00 
		$a_00_2 = {2f 53 6f 6c 6f 41 63 74 69 76 69 74 79 3b } //01 00 
		$a_00_3 = {2f 53 74 65 72 65 6f 52 65 63 65 69 76 65 72 3b } //00 00 
	condition:
		any of ($a_*)
 
}