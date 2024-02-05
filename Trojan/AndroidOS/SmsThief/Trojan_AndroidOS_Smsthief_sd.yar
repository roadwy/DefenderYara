
rule Trojan_AndroidOS_Smsthief_sd{
	meta:
		description = "Trojan:AndroidOS/Smsthief.sd,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 6d 73 5f 72 65 63 76 65 } //01 00 
		$a_01_1 = {6d 65 73 73 61 66 67 65 } //01 00 
		$a_01_2 = {73 75 63 63 65 73 73 66 75 6c 6c 79 20 72 65 67 69 73 74 65 72 65 64 } //00 00 
	condition:
		any of ($a_*)
 
}