
rule Trojan_AndroidOS_SmsAgent_D{
	meta:
		description = "Trojan:AndroidOS/SmsAgent.D,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 6f 62 6c 69 65 41 67 65 6e 74 5f 73 79 73 5f 63 6f 6e 66 69 67 } //01 00 
		$a_00_1 = {5f 70 61 79 5f 6c 6f 67 61 63 74 69 6f 6e } //01 00 
		$a_00_2 = {55 53 45 52 5f 53 54 41 54 55 53 5f 4c 4f 47 49 4e } //01 00 
		$a_00_3 = {67 65 74 44 65 66 61 75 6c 74 44 61 74 61 50 68 6f 6e 65 49 64 } //00 00 
		$a_00_4 = {5d 04 00 } //00 4b 
	condition:
		any of ($a_*)
 
}