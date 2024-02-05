
rule Trojan_AndroidOS_Dougalek_V_MTB{
	meta:
		description = "Trojan:AndroidOS/Dougalek.V!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 65 70 6f 74 2e 62 75 6c 6b 73 2e 6a 70 } //01 00 
		$a_00_1 = {4c 6a 70 2f 6f 6f 6d 6f 73 69 72 6f 64 6f 75 67 61 6d 61 74 6f 6d 65 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //00 00 
	condition:
		any of ($a_*)
 
}