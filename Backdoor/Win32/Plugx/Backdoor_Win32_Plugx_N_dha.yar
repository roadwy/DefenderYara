
rule Backdoor_Win32_Plugx_N_dha{
	meta:
		description = "Backdoor:Win32/Plugx.N!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {31 c0 8a 04 13 32 01 83 f8 00 75 0e 83 fa 00 74 04 49 4a } //01 00 
		$a_00_1 = {72 75 6e 64 6c 6c 33 32 20 22 25 73 22 20 41 63 74 69 76 65 51 76 61 77 20 22 25 73 22 } //01 00 
		$a_00_2 = {72 75 6e 64 6c 6c 33 32 20 22 25 73 22 20 50 6c 61 79 20 22 25 73 22 } //01 00 
		$a_01_3 = {53 65 6c 66 20 50 72 6f 63 65 73 73 20 49 64 3a 25 64 } //00 00 
		$a_00_4 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}