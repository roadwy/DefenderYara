
rule Backdoor_Win32_Joanap_D_dha{
	meta:
		description = "Backdoor:Win32/Joanap.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {99 f7 fd 8a 5c 0c 10 03 f3 8a 92 90 01 04 03 d6 81 e2 ff 00 00 00 41 8b f2 81 f9 00 01 00 00 8a 44 34 10 88 5c 34 10 88 44 0c 0f 7c 90 01 01 8b 94 24 18 01 00 00 33 f6 33 c0 85 d2 7e 90 00 } //01 00 
		$a_00_1 = {49 46 20 4e 4f 54 20 45 58 49 53 54 20 25 73 20 47 4f 54 4f 20 } //01 00 
		$a_00_2 = {52 54 5f 52 43 44 41 54 41 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Joanap_D_dha_2{
	meta:
		description = "Backdoor:Win32/Joanap.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {99 f7 fd 8a 5c 0c 10 03 f3 8a 92 90 01 04 03 d6 81 e2 ff 00 00 00 41 8b f2 81 f9 00 01 00 00 8a 44 34 10 88 5c 34 10 88 44 0c 0f 7c 90 01 01 8b 94 24 18 01 00 00 33 f6 33 c0 85 d2 7e 90 00 } //01 00 
		$a_00_1 = {49 46 20 4e 4f 54 20 45 58 49 53 54 20 25 73 20 47 4f 54 4f 20 } //01 00 
		$a_00_2 = {52 54 5f 52 43 44 41 54 41 } //00 00 
		$a_00_3 = {5d 04 00 } //00 da 
	condition:
		any of ($a_*)
 
}