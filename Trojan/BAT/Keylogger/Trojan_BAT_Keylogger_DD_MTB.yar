
rule Trojan_BAT_Keylogger_DD_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {13 39 11 31 6f 90 01 03 0a 13 3a 72 90 01 03 70 13 3b 17 13 3c 2b 16 72 90 01 03 70 13 52 72 90 01 03 70 13 53 72 90 01 03 70 13 54 00 11 3c 11 3a fe 02 16 fe 01 13 55 11 55 2d db 90 00 } //10
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_3 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}