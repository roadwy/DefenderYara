
rule Trojan_BAT_SnakeKeylogger_DO_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.DO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 09 00 00 "
		
	strings :
		$a_81_0 = {50 6f 72 74 61 6c 71 75 69 7a 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //10 Portalquiz.Properties.Resources
		$a_81_1 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_81_3 = {43 6f 6e 76 65 72 74 } //1 Convert
		$a_81_4 = {67 65 74 5f 4c 65 6e 67 74 68 } //1 get_Length
		$a_81_5 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_6 = {43 6f 6e 63 61 74 } //1 Concat
		$a_81_7 = {67 65 74 5f 58 } //1 get_X
		$a_81_8 = {67 65 74 5f 59 } //1 get_Y
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=15
 
}