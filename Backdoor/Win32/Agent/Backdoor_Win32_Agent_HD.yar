
rule Backdoor_Win32_Agent_HD{
	meta:
		description = "Backdoor:Win32/Agent.HD,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {80 34 11 18 03 ca 42 3b d0 7c f2 } //01 00 
		$a_02_1 = {8b 46 24 8b 4d 08 8d 04 48 0f b7 04 90 01 01 8b 90 01 01 1c 90 00 } //01 00 
		$a_00_2 = {5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b } //00 00  \System32\svchost.exe -k
	condition:
		any of ($a_*)
 
}