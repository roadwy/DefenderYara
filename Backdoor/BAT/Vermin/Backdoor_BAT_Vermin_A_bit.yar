
rule Backdoor_BAT_Vermin_A_bit{
	meta:
		description = "Backdoor:BAT/Vermin.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 75 6e 4b 65 79 4c 6f 67 67 65 72 } //01 00  RunKeyLogger
		$a_01_1 = {43 68 65 63 6b 49 66 50 72 6f 63 65 73 73 49 73 52 75 6e 6e 69 6e 67 } //01 00  CheckIfProcessIsRunning
		$a_01_2 = {53 74 61 72 74 43 61 70 74 75 72 65 53 63 72 65 65 6e } //01 00  StartCaptureScreen
		$a_01_3 = {53 74 61 72 74 41 75 64 69 6f 43 61 70 74 75 72 65 } //00 00  StartAudioCapture
	condition:
		any of ($a_*)
 
}