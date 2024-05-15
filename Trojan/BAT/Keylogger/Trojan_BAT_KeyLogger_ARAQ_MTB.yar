
rule Trojan_BAT_KeyLogger_ARAQ_MTB{
	meta:
		description = "Trojan:BAT/KeyLogger.ARAQ!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 02 00 "
		
	strings :
		$a_01_0 = {6b 00 65 00 79 00 73 00 74 00 72 00 6f 00 6b 00 65 00 73 00 2e 00 74 00 78 00 74 00 } //01 00  keystrokes.txt
		$a_01_1 = {5b 00 45 00 53 00 43 00 5d 00 } //01 00  [ESC]
		$a_01_2 = {5b 00 43 00 54 00 52 00 4c 00 5d 00 } //01 00  [CTRL]
		$a_01_3 = {5b 00 42 00 61 00 63 00 6b 00 5d 00 } //01 00  [Back]
		$a_01_4 = {5b 00 57 00 49 00 4e 00 5d 00 } //01 00  [WIN]
		$a_01_5 = {5b 00 54 00 61 00 62 00 5d 00 } //01 00  [Tab]
		$a_01_6 = {5b 00 44 00 45 00 4c 00 5d 00 } //02 00  [DEL]
		$a_01_7 = {4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 } //00 00  Keylogger
	condition:
		any of ($a_*)
 
}