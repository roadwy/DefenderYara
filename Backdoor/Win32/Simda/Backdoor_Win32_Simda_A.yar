
rule Backdoor_Win32_Simda_A{
	meta:
		description = "Backdoor:Win32/Simda.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 85 d2 7c 07 42 30 08 40 4a 75 fa c3 } //01 00 
		$a_03_1 = {4b 85 db 75 90 01 01 bb 90 01 02 00 00 b8 90 01 04 8b cb ba 90 01 02 00 00 e8 90 01 04 4b 85 db 75 90 01 01 6a 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Simda_A_2{
	meta:
		description = "Backdoor:Win32/Simda.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 85 d2 7c 07 42 30 08 40 4a 75 fa c3 } //01 00 
		$a_01_1 = {5a 38 d9 75 10 38 fd 75 0c c1 e9 10 c1 eb 10 38 d9 75 02 38 fd 5f 5e 5b } //01 00 
		$a_03_2 = {ff 4a f8 e8 90 01 04 5a 5f 5e 5b 58 8d 24 94 ff e0 c3 90 00 } //01 00 
		$a_03_3 = {85 c0 7e 24 50 83 c0 0a 83 e0 fe 50 e8 90 01 04 5a 66 c7 44 02 fe 00 00 83 c0 08 5a 89 50 fc c7 40 f8 01 00 00 00 c3 90 00 } //01 00 
		$a_11_4 = {4c 67 47 30 30 43 30 30 30 30 34 30 30 30 30 2f 2f 79 30 30 42 57 30 30 30 30 30 30 30 30 30 47 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 00 } //00 7e  杌ぇ䌰〰〰〴〰⼰礯〰坂〰〰〰〰䜰〰〰〰〰〰〰〰0
	condition:
		any of ($a_*)
 
}