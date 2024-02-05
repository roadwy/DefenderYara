
rule Trojan_AndroidOS_SmsThief_E_MTB{
	meta:
		description = "Trojan:AndroidOS/SmsThief.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 61 75 74 6f 6f 2f 75 70 64 61 74 65 } //01 00 
		$a_01_1 = {56 69 64 65 6f 48 32 36 33 41 63 74 69 76 69 74 79 } //01 00 
		$a_01_2 = {69 6e 69 74 69 61 6c 69 7a 65 56 69 64 65 6f 46 6f 72 53 61 6e 58 69 6e 67 53 36 } //01 00 
		$a_01_3 = {63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 73 65 72 76 69 63 65 2f 48 65 6c 6c 6f 53 65 72 76 69 63 65 } //01 00 
		$a_01_4 = {6d 6e 74 2f 73 64 63 61 72 64 2f 70 6b 34 66 75 6e 73 } //01 00 
		$a_01_5 = {2f 66 69 6c 65 73 4d 61 6e 61 67 65 72 2f 75 70 6c 6f 61 64 46 69 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}