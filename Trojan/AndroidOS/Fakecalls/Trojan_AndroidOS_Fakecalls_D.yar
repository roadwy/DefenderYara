
rule Trojan_AndroidOS_Fakecalls_D{
	meta:
		description = "Trojan:AndroidOS/Fakecalls.D,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 55 70 64 61 74 65 54 69 6d 65 } //01 00 
		$a_01_1 = {42 6c 61 63 6b 4c 69 73 74 } //01 00 
		$a_01_2 = {73 65 74 52 65 63 65 69 76 65 42 6c 6f 63 6b } //01 00 
		$a_01_3 = {4e 75 6d 62 65 72 4c 69 73 74 } //00 00 
	condition:
		any of ($a_*)
 
}