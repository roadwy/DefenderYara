
rule Backdoor_Win32_Joanap_E_dha{
	meta:
		description = "Backdoor:Win32/Joanap.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 5c 4b 42 44 5f 25 73 5f 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 2e 43 41 54 } //01 00 
		$a_00_1 = {7e 25 6c 64 28 25 6c 64 25 25 29 } //01 00 
		$a_00_2 = {25 73 5c 6f 65 6d 2a 2e 2a } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Joanap_E_dha_2{
	meta:
		description = "Backdoor:Win32/Joanap.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 5c 4b 42 44 5f 25 73 5f 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 2e 43 41 54 } //01 00 
		$a_00_1 = {7e 25 6c 64 28 25 6c 64 25 25 29 } //01 00 
		$a_00_2 = {25 73 5c 6f 65 6d 2a 2e 2a } //00 00 
		$a_00_3 = {5d 04 00 } //00 ec 
	condition:
		any of ($a_*)
 
}