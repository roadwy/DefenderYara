
rule Trojan_AndroidOS_SmsThief_J{
	meta:
		description = "Trojan:AndroidOS/SmsThief.J,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {72 65 74 72 79 67 65 74 70 65 72 6d 69 73 73 69 6f 6e } //02 00 
		$a_01_1 = {6d 79 74 65 73 74 70 72 6f 6a 65 63 74 73 2e 78 79 7a } //02 00 
		$a_01_2 = {74 65 73 74 66 69 72 65 62 61 73 65 2f 53 6d 73 50 72 6f 63 65 73 73 53 65 72 76 69 63 65 3b } //00 00 
	condition:
		any of ($a_*)
 
}