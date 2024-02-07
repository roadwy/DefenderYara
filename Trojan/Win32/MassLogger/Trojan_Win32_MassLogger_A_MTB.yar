
rule Trojan_Win32_MassLogger_A_MTB{
	meta:
		description = "Trojan:Win32/MassLogger.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {4d 61 73 73 4c 6f 67 67 65 72 20 45 78 69 74 20 61 66 74 65 72 20 64 65 6c 69 76 65 72 79 3a } //01 00  MassLogger Exit after delivery:
		$a_81_1 = {4d 61 73 73 4c 6f 67 67 65 72 20 50 72 6f 63 65 73 73 3a } //01 00  MassLogger Process:
		$a_81_2 = {4d 61 73 73 4c 6f 67 67 65 72 20 53 74 61 72 74 65 64 3a } //01 00  MassLogger Started:
		$a_81_3 = {4c 6f 67 67 65 72 20 44 65 74 61 69 6c 73 } //01 00  Logger Details
		$a_81_4 = {4b 65 79 6c 6f 67 67 65 72 20 41 6e 64 20 43 6c 69 70 62 6f 61 72 64 } //00 00  Keylogger And Clipboard
	condition:
		any of ($a_*)
 
}