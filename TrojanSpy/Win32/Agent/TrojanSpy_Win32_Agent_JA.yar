
rule TrojanSpy_Win32_Agent_JA{
	meta:
		description = "TrojanSpy:Win32/Agent.JA,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {7c 4f 70 74 69 6f 6e 73 2e 49 6e 66 65 63 74 46 69 6c 65 73 3d } //01 00  |Options.InfectFiles=
		$a_01_1 = {4b 65 79 4c 6f 67 67 65 72 2e 41 63 74 69 76 65 } //01 00  KeyLogger.Active
		$a_01_2 = {7c 4f 70 74 69 6f 6e 73 2e 44 65 61 63 74 69 76 65 4b 61 73 70 65 72 53 6b 79 3d } //01 00  |Options.DeactiveKasperSky=
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //00 00  Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		any of ($a_*)
 
}