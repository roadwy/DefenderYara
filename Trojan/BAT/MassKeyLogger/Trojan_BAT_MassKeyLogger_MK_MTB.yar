
rule Trojan_BAT_MassKeyLogger_MK_MTB{
	meta:
		description = "Trojan:BAT/MassKeyLogger.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 61 73 73 4c 6f 67 67 65 72 } //01 00  MassLogger
		$a_01_1 = {6c 6f 67 67 65 72 44 61 74 61 } //01 00  loggerData
		$a_01_2 = {5f 68 6f 6f 6b 49 44 } //01 00  _hookID
		$a_01_3 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //01 00  SetWindowsHookEx
		$a_01_4 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //01 00  CallNextHookEx
		$a_01_5 = {53 79 73 74 65 6d 2e 4e 65 74 2e 4d 61 69 6c } //01 00  System.Net.Mail
		$a_01_6 = {4e 65 74 77 6f 72 6b 43 72 65 64 65 6e 74 69 61 6c } //01 00  NetworkCredential
		$a_01_7 = {45 6e 61 62 6c 65 41 6e 74 69 53 61 6e 64 62 6f 78 69 65 } //01 00  EnableAntiSandboxie
		$a_01_8 = {45 6e 61 62 6c 65 57 44 45 78 63 6c 75 73 69 6f 6e } //01 00  EnableWDExclusion
		$a_01_9 = {45 6e 61 62 6c 65 4b 65 79 6c 6f 67 67 65 72 } //01 00  EnableKeylogger
		$a_03_10 = {4d 61 73 73 4c 6f 67 67 65 72 90 02 14 72 65 73 6f 75 72 63 65 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}