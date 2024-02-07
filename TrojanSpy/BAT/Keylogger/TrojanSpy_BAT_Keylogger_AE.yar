
rule TrojanSpy_BAT_Keylogger_AE{
	meta:
		description = "TrojanSpy:BAT/Keylogger.AE,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 00 63 00 72 00 65 00 6e 00 3d 00 63 00 61 00 70 00 74 00 75 00 72 00 65 00 64 00 53 00 63 00 72 00 65 00 65 00 6e 00 } //01 00  scren=capturedScreen
		$a_01_1 = {68 00 61 00 73 00 63 00 61 00 6d 00 3d 00 68 00 61 00 73 00 63 00 61 00 6d 00 } //01 00  hascam=hascam
		$a_01_2 = {75 00 6b 00 6c 00 6f 00 67 00 3d 00 73 00 65 00 6e 00 64 00 } //01 00  uklog=send
		$a_01_3 = {73 65 6e 64 50 61 73 73 4c 6f 67 73 } //01 00  sendPassLogs
		$a_01_4 = {73 65 6e 64 53 63 72 65 65 6e } //01 00  sendScreen
		$a_01_5 = {73 65 6e 64 4b 65 79 4c 6f 67 73 } //01 00  sendKeyLogs
		$a_01_6 = {73 65 6e 64 43 61 6d } //00 00  sendCam
		$a_00_7 = {5d 04 00 } //00 1e 
	condition:
		any of ($a_*)
 
}