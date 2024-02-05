
rule Backdoor_Win32_Odelns_A_dha{
	meta:
		description = "Backdoor:Win32/Odelns.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 73 70 6f 6f 6c 73 76 2e 64 6c 6c 00 00 00 00 5b 44 45 4c 5d 00 00 00 5b 49 4e 53 5d } //01 00 
		$a_01_1 = {2d 2d 2d 5b 20 25 73 20 5d 2d 2d 2d 25 34 64 2f 25 30 32 64 2f 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 } //01 00 
		$a_03_2 = {81 fd 02 02 00 00 0f 85 b6 00 00 00 ff d6 8b f0 a1 90 01 03 00 3b c6 0f 84 a5 00 00 00 8d 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}