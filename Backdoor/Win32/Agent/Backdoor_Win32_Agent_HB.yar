
rule Backdoor_Win32_Agent_HB{
	meta:
		description = "Backdoor:Win32/Agent.HB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 14 01 80 f2 62 88 14 01 41 81 f9 90 01 02 00 00 76 ee 90 00 } //01 00 
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 67 68 30 73 74 } //01 00  SOFTWARE\Microsoft\gh0st
		$a_00_2 = {43 6f 6d 72 65 73 2e 64 6c 6c } //00 00  Comres.dll
	condition:
		any of ($a_*)
 
}