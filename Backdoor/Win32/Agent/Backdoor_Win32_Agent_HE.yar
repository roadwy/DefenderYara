
rule Backdoor_Win32_Agent_HE{
	meta:
		description = "Backdoor:Win32/Agent.HE,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {69 6e 20 49 63 6d 70 50 61 63 6b 46 6c 6f 6f 64 28 29 } //01 00 
		$a_00_1 = {72 65 6e 61 6d 65 20 22 25 73 22 20 22 25 73 2e 65 78 65 22 } //01 00 
		$a_00_2 = {5c 63 74 66 6d 6f 6e 2e 65 78 65 } //01 00 
		$a_00_3 = {00 5f 73 76 72 2e 64 61 74 00 } //01 00 
		$a_01_4 = {80 33 25 43 } //00 00 
	condition:
		any of ($a_*)
 
}