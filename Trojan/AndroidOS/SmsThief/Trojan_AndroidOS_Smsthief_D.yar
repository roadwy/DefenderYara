
rule Trojan_AndroidOS_Smsthief_D{
	meta:
		description = "Trojan:AndroidOS/Smsthief.D,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {62 74 6e 62 65 66 6f 72 70 61 79 } //02 00 
		$a_01_1 = {63 6f 6d 2e 7a 65 72 6f 6f 6e 65 2e 64 69 76 61 72 61 6f 70 2e 53 70 6c 61 73 68 41 63 74 69 76 69 74 79 41 6c 69 61 73 } //02 00 
		$a_01_2 = {69 72 64 76 73 76 65 73 2e 63 66 2f 72 65 73 70 6f 6e 2e 70 68 70 } //00 00 
	condition:
		any of ($a_*)
 
}