
rule Trojan_BAT_SnakeKeylogger_DZ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.DZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {42 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 42 } //1 B________________________B
		$a_81_1 = {53 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 53 } //1 S____________________________S
		$a_81_2 = {44 69 61 6c 6f 67 73 4c 69 62 } //1 DialogsLib
		$a_81_3 = {4b 65 79 45 76 65 6e 74 41 72 67 73 } //1 KeyEventArgs
		$a_81_4 = {4b 65 79 45 76 65 6e 74 48 61 6e 64 6c 65 72 } //1 KeyEventHandler
		$a_81_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_6 = {53 75 73 70 65 6e 64 4c 61 79 6f 75 74 } //1 SuspendLayout
		$a_81_7 = {54 6f 42 79 74 65 } //1 ToByte
		$a_81_8 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_9 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}