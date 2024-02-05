
rule Trojan_AndroidOS_Smsthief_Y{
	meta:
		description = "Trojan:AndroidOS/Smsthief.Y,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 70 72 6e 63 2e 68 69 64 65 69 63 6f 6e } //01 00 
		$a_01_1 = {7a 78 7a 78 7a 78 6e 6f 74 73 65 6e 64 } //01 00 
		$a_01_2 = {75 70 69 70 69 6e 64 65 6b 68 } //00 00 
	condition:
		any of ($a_*)
 
}