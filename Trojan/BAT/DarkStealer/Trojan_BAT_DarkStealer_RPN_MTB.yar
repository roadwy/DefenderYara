
rule Trojan_BAT_DarkStealer_RPN_MTB{
	meta:
		description = "Trojan:BAT/DarkStealer.RPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 04 08 5d 91 07 04 1f 16 5d 91 61 28 1f 00 00 0a 03 04 17 58 08 5d 91 28 20 00 00 0a 59 06 58 06 5d d2 0d 2b 00 09 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkStealer_RPN_MTB_2{
	meta:
		description = "Trojan:BAT/DarkStealer.RPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {05 49 00 6e 00 00 05 76 00 6f 00 00 05 6b 00 65 00 } //1
		$a_01_1 = {47 00 65 00 74 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //1 GetString
		$a_01_2 = {4c 00 65 00 6e 00 67 00 74 00 68 00 } //1 Length
		$a_01_3 = {63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 69 00 6e 00 69 00 } //1 config.ini
		$a_01_4 = {6c 00 6f 00 67 00 2e 00 74 00 78 00 74 00 } //1 log.txt
		$a_01_5 = {43 00 6f 00 75 00 6c 00 64 00 20 00 6e 00 6f 00 74 00 20 00 73 00 65 00 74 00 20 00 6b 00 65 00 79 00 62 00 6f 00 61 00 72 00 64 00 20 00 68 00 6f 00 6f 00 6b 00 } //1 Could not set keyboard hook
		$a_01_6 = {53 00 74 00 61 00 72 00 74 00 20 00 52 00 65 00 63 00 6f 00 72 00 64 00 69 00 6e 00 67 00 } //1 Start Recording
		$a_01_7 = {5c 00 5c 00 73 00 63 00 72 00 65 00 65 00 6e 00 73 00 5c 00 5c 00 6d 00 69 00 73 00 63 00 } //1 \\screens\\misc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}