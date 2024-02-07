
rule Backdoor_Win32_Agent_GG{
	meta:
		description = "Backdoor:Win32/Agent.GG,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 04 2a 8b fe fe c0 43 88 02 83 c9 ff } //01 00 
		$a_01_1 = {5c 53 79 73 74 65 6d 33 32 5c 54 72 6b 57 63 73 2e 65 78 } //00 00  \System32\TrkWcs.ex
	condition:
		any of ($a_*)
 
}