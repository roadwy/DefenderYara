
rule Trojan_Win32_KeyLogger_LM_MTB{
	meta:
		description = "Trojan:Win32/KeyLogger.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,24 00 24 00 08 00 00 "
		
	strings :
		$a_81_0 = {4b 65 79 6c 6f 67 67 65 72 20 69 6e 69 74 69 61 6c 69 7a 61 74 69 6f 6e 20 66 61 69 6c 75 72 65 3a 20 65 72 72 6f 72 } //1 Keylogger initialization failure: error
		$a_81_1 = {4b 65 79 6c 6f 67 67 65 72 20 53 74 6f 70 70 65 64 } //2 Keylogger Stopped
		$a_81_2 = {5b 54 65 78 74 20 50 61 73 74 65 64 20 46 72 6f 6d 20 43 6c 69 70 62 6f 61 72 64 5d } //3 [Text Pasted From Clipboard]
		$a_81_3 = {5b 54 65 78 74 20 63 6f 70 69 65 64 20 74 6f 20 63 6c 69 70 62 6f 61 72 64 5d } //4 [Text copied to clipboard]
		$a_81_4 = {2a 20 56 69 6f 74 74 6f 4b 65 79 6c 6f 67 67 65 72 20 76 } //5 * ViottoKeylogger v
		$a_81_5 = {4b 65 79 6c 6f 67 67 65 72 20 53 74 61 72 74 65 64 } //6 Keylogger Started
		$a_81_6 = {7b 55 73 65 72 20 77 61 73 20 69 64 6c 65 20 66 6f 72 } //7 {User was idle for
		$a_81_7 = {6c 6f 67 5f 25 30 34 69 2e 25 30 32 69 2e 25 30 32 69 5f 25 30 32 69 2e 25 30 32 69 2e 74 78 74 } //8 log_%04i.%02i.%02i_%02i.%02i.txt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*2+(#a_81_2  & 1)*3+(#a_81_3  & 1)*4+(#a_81_4  & 1)*5+(#a_81_5  & 1)*6+(#a_81_6  & 1)*7+(#a_81_7  & 1)*8) >=36
 
}