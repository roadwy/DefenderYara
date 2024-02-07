
rule Backdoor_Win32_Agent_HC{
	meta:
		description = "Backdoor:Win32/Agent.HC,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {80 30 26 40 3d 90 01 04 72 f5 e9 90 00 } //01 00 
		$a_00_1 = {33 d2 f7 75 0c 8b 45 08 85 d2 74 0a } //01 00 
		$a_00_2 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //00 00  SetThreadContext
	condition:
		any of ($a_*)
 
}