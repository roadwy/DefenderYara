
rule TrojanDropper_Win32_Nanocore_A{
	meta:
		description = "TrojanDropper:Win32/Nanocore.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {36 41 38 34 2e 2f 37 42 4b 38 } //01 00  6A84./7BK8
		$a_01_1 = {77 61 76 65 49 6e 41 64 64 42 75 66 66 65 72 32 } //01 00  waveInAddBuffer2
		$a_01_2 = {45 56 45 4e 54 5f 53 49 4e 4b 5f 51 75 65 72 79 49 6e 74 65 72 66 61 63 65 } //00 00  EVENT_SINK_QueryInterface
	condition:
		any of ($a_*)
 
}