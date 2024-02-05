
rule Trojan_AndroidOS_SmsThief_H{
	meta:
		description = "Trojan:AndroidOS/SmsThief.H,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {69 6e 64 65 78 2e 70 68 70 2f 69 6e 64 65 78 2f 73 6d 73 2f 73 61 76 65 73 6d 73 } //02 00 
		$a_01_1 = {63 6f 6d 2e 73 65 63 6f 6d 6d 65 72 63 65 2e 65 63 6f 6d 6d 65 72 63 65 } //02 00 
		$a_01_2 = {6c 61 73 74 50 6f 73 74 53 6d 73 49 64 } //00 00 
	condition:
		any of ($a_*)
 
}