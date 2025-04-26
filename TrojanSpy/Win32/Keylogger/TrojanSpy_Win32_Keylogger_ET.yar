
rule TrojanSpy_Win32_Keylogger_ET{
	meta:
		description = "TrojanSpy:Win32/Keylogger.ET,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 65 76 65 6e 4d 75 74 65 78 } //1 SevenMutex
		$a_01_1 = {42 55 47 47 65 74 4b 65 79 } //1 BUGGetKey
		$a_00_2 = {3a 5b 25 73 5d 49 50 3a 5b 25 73 5d 2d 25 73 } //1 :[%s]IP:[%s]-%s
		$a_00_3 = {3c 45 6e 74 65 72 3e } //1 <Enter>
		$a_00_4 = {3c 43 54 52 4c 3e } //1 <CTRL>
		$a_01_5 = {53 65 76 65 6e 6c 69 6e 6b } //1 Sevenlink
		$a_01_6 = {70 73 6d 74 70 69 6e 66 6f 2d 3e 4d 73 67 } //1 psmtpinfo->Msg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}