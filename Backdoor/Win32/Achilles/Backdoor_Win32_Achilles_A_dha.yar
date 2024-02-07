
rule Backdoor_Win32_Achilles_A_dha{
	meta:
		description = "Backdoor:Win32/Achilles.A!dha,SIGNATURE_TYPE_PEHSTR,ffffffe8 03 ffffffe8 03 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 00 6f 00 67 00 69 00 6e 00 20 00 62 00 79 00 20 00 75 00 73 00 65 00 72 00 20 00 61 00 6e 00 64 00 20 00 70 00 77 00 64 00 20 00 66 00 61 00 69 00 6c 00 65 00 64 00 } //01 00  login by user and pwd failed
		$a_01_1 = {67 00 65 00 74 00 20 00 74 00 68 00 65 00 20 00 74 00 61 00 72 00 67 00 65 00 74 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 62 00 75 00 74 00 20 00 63 00 61 00 6e 00 27 00 74 00 20 00 6f 00 70 00 65 00 6e 00 20 00 69 00 74 00 3a 00 25 00 64 00 } //01 00  get the target process but can't open it:%d
		$a_01_2 = {3a 00 73 00 68 00 65 00 6c 00 6c 00 63 00 6f 00 64 00 65 00 } //01 00  :shellcode
		$a_01_3 = {41 63 68 69 6c 6c 65 73 } //01 00  Achilles
		$a_01_4 = {47 6c 6f 62 61 6c 5c 6b 69 6c 6c 5f 25 30 2e 38 64 5f 61 64 73 66 } //01 00  Global\kill_%0.8d_adsf
		$a_01_5 = {47 45 54 20 5c 44 4f 4f 4d 20 48 54 54 50 31 2f 31 } //00 00  GET \DOOM HTTP1/1
		$a_01_6 = {00 5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}