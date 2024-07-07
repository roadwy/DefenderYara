
rule Trojan_BAT_SnakeKeylogger_EF_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.EF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1d 00 1d 00 0b 00 00 "
		
	strings :
		$a_81_0 = {57 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 57 } //10 W__________W
		$a_81_1 = {58 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 58 } //10 X__________X
		$a_81_2 = {4b 65 79 45 76 65 6e 74 48 61 6e 64 6c 65 72 } //1 KeyEventHandler
		$a_81_3 = {4d 6f 75 73 65 45 76 65 6e 74 48 61 6e 64 6c 65 72 } //1 MouseEventHandler
		$a_81_4 = {4b 65 79 45 76 65 6e 74 41 72 67 73 } //1 KeyEventArgs
		$a_81_5 = {4d 6f 75 73 65 45 76 65 6e 74 41 72 67 73 } //1 MouseEventArgs
		$a_81_6 = {4f 6e 4b 65 79 50 72 65 73 73 } //1 OnKeyPress
		$a_81_7 = {61 64 64 5f 4d 6f 75 73 65 43 6c 69 63 6b } //1 add_MouseClick
		$a_81_8 = {67 65 74 5f 4b 65 79 73 } //1 get_Keys
		$a_81_9 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_10 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=29
 
}