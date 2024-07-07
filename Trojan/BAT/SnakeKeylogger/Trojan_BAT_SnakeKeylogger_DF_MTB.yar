
rule Trojan_BAT_SnakeKeylogger_DF_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {57 69 6e 46 6f 72 6d 73 53 79 6e 74 61 78 48 69 67 68 6c 69 67 68 74 65 72 } //1 WinFormsSyntaxHighlighter
		$a_81_1 = {65 67 6f 6c 64 73 } //1 egolds
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_3 = {59 6f 75 20 61 72 65 20 41 77 65 73 6f 6d 65 } //1 You are Awesome
		$a_81_4 = {43 6f 6e 76 65 72 74 } //1 Convert
		$a_81_5 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_6 = {53 70 6c 69 74 } //1 Split
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}