
rule Trojan_BAT_SnakeKeylogger_DK_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {53 65 63 75 72 65 4c 69 66 65 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 SecureLife.My.Resources
		$a_81_1 = {00 69 69 69 69 69 69 00 } //1 椀楩楩i
		$a_81_2 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_5 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_6 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_7 = {43 6f 6e 76 65 72 74 } //1 Convert
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}