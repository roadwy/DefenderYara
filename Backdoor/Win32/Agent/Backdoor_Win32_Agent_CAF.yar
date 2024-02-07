
rule Backdoor_Win32_Agent_CAF{
	meta:
		description = "Backdoor:Win32/Agent.CAF,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 79 73 40 55 73 65 72 20 3a 20 25 73 40 25 73 20 28 25 73 29 } //01 00  Sys@User : %s@%s (%s)
		$a_01_1 = {50 69 6e 67 20 73 65 63 20 3a 20 25 34 64 6d 73 20 25 34 64 6d 73 20 25 34 64 6d 73 20 2d 3e 20 20 61 76 65 72 61 67 65 25 34 64 6d 73 } //01 00  Ping sec : %4dms %4dms %4dms ->  average%4dms
		$a_01_2 = {73 25 34 64 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 2e 6a 70 67 } //01 00  s%4d%02d%02d%02d%02d%02d.jpg
		$a_01_3 = {64 64 69 72 20 63 3a 5c 6d 79 20 64 6f 63 75 6d 65 6e 74 73 } //01 00  ddir c:\my documents
		$a_01_4 = {75 6e 64 65 6c 64 69 72 25 64 2e 68 74 6d 6c } //01 00  undeldir%d.html
		$a_01_5 = {78 65 63 75 72 65 20 73 73 6c } //00 00  xecure ssl
		$a_00_6 = {5d 04 00 00 } //48 b6 
	condition:
		any of ($a_*)
 
}