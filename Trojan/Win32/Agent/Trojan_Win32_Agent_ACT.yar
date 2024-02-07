
rule Trojan_Win32_Agent_ACT{
	meta:
		description = "Trojan:Win32/Agent.ACT,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //01 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {44 32 46 41 43 30 32 34 2d 39 32 43 30 2d 34 32 45 35 2d 41 37 35 42 2d 37 42 34 45 33 39 31 35 43 43 35 30 } //01 00  D2FAC024-92C0-42E5-A75B-7B4E3915CC50
		$a_01_2 = {6d 69 63 72 6f 62 69 6c 6c 73 79 73 2e 63 6f 6d } //01 00  microbillsys.com
		$a_01_3 = {6d 69 62 72 73 79 73 2e 65 78 65 } //01 00  mibrsys.exe
		$a_01_4 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //01 00  CreateMutexA
		$a_01_5 = {49 6e 74 65 72 6e 65 74 47 65 74 43 6f 6e 6e 65 63 74 65 64 53 74 61 74 65 } //00 00  InternetGetConnectedState
	condition:
		any of ($a_*)
 
}