
rule Trojan_AndroidOS_InfoStealer_S{
	meta:
		description = "Trojan:AndroidOS/InfoStealer.S,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 74 61 72 74 53 61 6c 65 73 53 74 61 74 69 73 53 65 72 76 69 63 65 } //01 00 
		$a_00_1 = {53 45 4e 44 5f 53 4d 53 5f 44 45 4c 41 59 5f 54 49 4d 45 } //01 00 
		$a_00_2 = {43 6c 69 63 6b 53 69 6d 53 74 61 74 65 53 65 72 76 69 63 65 } //01 00 
		$a_00_3 = {43 48 41 4e 4e 45 4c 43 4f 44 45 5f 46 49 4c 45 4e 41 4d 45 } //00 00 
	condition:
		any of ($a_*)
 
}