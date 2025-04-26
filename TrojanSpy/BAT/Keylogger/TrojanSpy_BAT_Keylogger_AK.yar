
rule TrojanSpy_BAT_Keylogger_AK{
	meta:
		description = "TrojanSpy:BAT/Keylogger.AK,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 74 4b 65 79 4c 6f 67 67 65 72 } //1 StartKeyLogger
		$a_01_1 = {53 74 6f 70 44 65 74 65 63 74 4d 79 56 69 72 75 73 } //1 StopDetectMyVirus
		$a_01_2 = {4e 74 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 } //1 NtSetInformationProcess
		$a_03_3 = {1f 1d 0f 00 1a 28 ?? 00 00 06 } //1
		$a_03_4 = {1f 1d 0f 01 1a 28 ?? 00 00 06 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}