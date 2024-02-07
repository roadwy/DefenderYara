
rule Backdoor_Win32_Agent_GS{
	meta:
		description = "Backdoor:Win32/Agent.GS,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 33 33 30 00 00 00 00 6d 79 72 61 74 2e 64 79 6e 64 6e 73 2e 6f 72 67 } //01 00 
		$a_01_1 = {47 6c 6f 62 61 6c 5c 73 65 72 76 65 72 } //00 00  Global\server
	condition:
		any of ($a_*)
 
}