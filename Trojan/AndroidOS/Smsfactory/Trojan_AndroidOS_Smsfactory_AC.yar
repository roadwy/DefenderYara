
rule Trojan_AndroidOS_Smsfactory_AC{
	meta:
		description = "Trojan:AndroidOS/Smsfactory.AC,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {6d 65 6e 75 73 5f 73 74 65 70 } //01 00 
		$a_00_1 = {61 70 70 5f 64 62 3d 61 70 6b 73 5f 64 61 74 61 } //01 00 
		$a_00_2 = {64 65 76 69 63 65 73 5f 71 75 65 73 74 69 6f 6e } //01 00 
		$a_00_3 = {70 72 6f 67 72 61 6d 6d 65 64 5f 6a 6f 62 } //00 00 
	condition:
		any of ($a_*)
 
}