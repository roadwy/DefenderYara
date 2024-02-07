
rule Backdoor_Win32_Agent_GT{
	meta:
		description = "Backdoor:Win32/Agent.GT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 33 33 30 00 00 6d 79 52 41 54 } //01 00 
		$a_01_1 = {57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 5c 75 70 64 61 74 65 2e 65 78 65 } //00 00  Windows Update\update.exe
	condition:
		any of ($a_*)
 
}