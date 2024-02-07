
rule Backdoor_BAT_Boilod_A{
	meta:
		description = "Backdoor:BAT/Boilod.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 65 79 6c 6f 67 67 65 72 } //01 00  Keylogger
		$a_01_1 = {57 65 62 63 61 6d } //01 00  Webcam
		$a_01_2 = {50 61 73 73 77 6f 72 64 52 65 63 6f 76 65 72 79 } //01 00  PasswordRecovery
		$a_01_3 = {53 74 61 72 74 4d 69 6e 65 72 } //01 00  StartMiner
		$a_01_4 = {53 65 6e 64 53 63 72 65 65 6e } //01 00  SendScreen
		$a_01_5 = {53 74 61 72 74 53 63 61 6e } //01 00  StartScan
		$a_01_6 = {53 70 79 77 61 72 65 } //01 00  Spyware
		$a_01_7 = {64 6c 45 78 65 63 75 74 65 } //01 00  dlExecute
		$a_01_8 = {53 68 6f 77 43 68 61 74 } //01 00  ShowChat
		$a_01_9 = {53 74 61 72 74 50 72 6f 78 79 } //00 00  StartProxy
		$a_00_10 = {80 10 00 00 } //bb ff 
	condition:
		any of ($a_*)
 
}