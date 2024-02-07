
rule TrojanDropper_Win32_Teamspy_A_bit{
	meta:
		description = "TrojanDropper:Win32/Teamspy.A!bit,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 65 78 74 72 61 63 74 5f 63 6c 65 61 6e 75 70 25 64 } //01 00  wextract_cleanup%d
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //01 00  Software\Microsoft\Windows\CurrentVersion\RunOnce
		$a_01_2 = {45 58 45 20 2f 76 65 72 79 73 69 6c 65 6e 74 20 2f 50 61 73 73 77 6f 72 64 3d 31 32 33 34 35 32 32 32 32 32 } //00 00  EXE /verysilent /Password=1234522222
	condition:
		any of ($a_*)
 
}