
rule Trojan_Win32_Pikabot_YAQ_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.YAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 72 61 73 68 } //01 00  Crash
		$a_01_1 = {62 65 4e 6f 74 69 66 69 65 64 } //01 00  beNotified
		$a_01_2 = {67 65 74 46 75 6e 63 73 41 72 72 61 79 } //01 00  getFuncsArray
		$a_01_3 = {69 73 55 6e 69 63 6f 64 65 } //01 00  isUnicode
		$a_01_4 = {6d 65 73 73 61 67 65 50 72 6f 63 } //01 00  messageProc
		$a_01_5 = {73 65 74 49 6e 66 6f } //01 00  setInfo
		$a_01_6 = {67 65 74 4e 61 6d 65 } //01 00  getName
		$a_01_7 = {50 ff d7 85 c0 75 20 46 81 fe 61 e6 01 00 7c d4 50 6a 01 50 } //00 00 
	condition:
		any of ($a_*)
 
}