
rule Trojan_AndroidOS_Fakecalls_M{
	meta:
		description = "Trojan:AndroidOS/Fakecalls.M,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {63 68 65 63 6b 57 68 6f 57 68 6f 53 74 61 74 75 73 } //02 00 
		$a_01_1 = {69 73 49 6e 73 74 61 6c 6c 65 64 57 68 6f 57 68 6f } //02 00 
		$a_01_2 = {72 75 6e 57 68 6f 57 68 6f } //02 00 
		$a_01_3 = {72 65 71 75 65 73 74 49 6e 73 74 61 6c 6c 55 6e 6b 6e 6f 77 6e 41 70 70 } //00 00 
	condition:
		any of ($a_*)
 
}