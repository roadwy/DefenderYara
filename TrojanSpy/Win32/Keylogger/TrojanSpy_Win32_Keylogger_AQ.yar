
rule TrojanSpy_Win32_Keylogger_AQ{
	meta:
		description = "TrojanSpy:Win32/Keylogger.AQ,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 53 74 75 64 69 6f 5c 56 42 39 38 5c 56 42 36 2e 4f 4c 42 } //01 00  Microsoft Visual Studio\VB98\VB6.OLB
		$a_01_1 = {68 69 64 65 66 72 6f 6d 70 72 6f 63 65 73 73 6c 69 73 74 } //01 00  hidefromprocesslist
		$a_01_2 = {73 6d 74 70 2e 73 6f 6d 65 73 65 72 76 65 72 2e 73 6f 6d 65 74 68 69 6e 67 } //01 00  smtp.someserver.something
		$a_01_3 = {6b 65 79 6c 6f 67 72 65 70 6f 72 74 } //01 00  keylogreport
		$a_01_4 = {65 6d 61 69 6c 40 73 6f 6d 65 73 65 72 76 65 72 } //01 00  email@someserver
		$a_01_5 = {6b 00 65 00 79 00 20 00 6c 00 6f 00 67 00 67 00 65 00 72 00 20 00 70 00 72 00 6f 00 6a 00 65 00 63 00 74 00 5c 00 6c 00 6f 00 67 00 67 00 65 00 72 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //01 00  key logger project\logger\Project1.vbp
		$a_01_6 = {37 00 38 00 45 00 31 00 42 00 44 00 44 00 31 00 2d 00 39 00 39 00 34 00 31 00 2d 00 31 00 31 00 63 00 66 00 2d 00 39 00 37 00 35 00 36 00 2d 00 30 00 30 00 41 00 41 00 30 00 30 00 43 00 30 00 30 00 39 00 30 00 } //00 00  78E1BDD1-9941-11cf-9756-00AA00C0090
	condition:
		any of ($a_*)
 
}