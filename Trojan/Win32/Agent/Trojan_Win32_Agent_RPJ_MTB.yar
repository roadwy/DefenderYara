
rule Trojan_Win32_Agent_RPJ_MTB{
	meta:
		description = "Trojan:Win32/Agent.RPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 3a 5c 57 6f 72 6b 73 70 61 63 65 5c 43 72 79 70 74 65 64 5c 61 2e 70 64 62 } //01 00 
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00 
		$a_01_2 = {77 63 66 67 6d 67 72 33 32 2e 65 78 65 } //01 00 
		$a_01_3 = {6c 73 74 72 6c 65 6e 41 } //01 00 
		$a_01_4 = {53 6c 65 65 70 } //01 00 
		$a_01_5 = {6d 61 6c 6c 6f 63 } //00 00 
	condition:
		any of ($a_*)
 
}