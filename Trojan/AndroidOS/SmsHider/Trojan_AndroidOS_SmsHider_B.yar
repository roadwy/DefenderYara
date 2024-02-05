
rule Trojan_AndroidOS_SmsHider_B{
	meta:
		description = "Trojan:AndroidOS/SmsHider.B,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {73 76 72 2e 6d 6f 73 69 6a 69 65 2e 63 6f 6d 2f 90 03 06 08 4e 6f 74 69 63 65 46 6f 72 65 75 6e 65 72 2f 90 00 } //01 00 
		$a_01_1 = {68 69 64 65 72 2e 41 70 70 49 6e 73 74 61 6c 6c } //01 00 
		$a_01_2 = {6e 65 74 77 6f 72 6b 20 69 73 20 6e 6f 74 20 77 6f 72 6b 21 } //00 00 
	condition:
		any of ($a_*)
 
}