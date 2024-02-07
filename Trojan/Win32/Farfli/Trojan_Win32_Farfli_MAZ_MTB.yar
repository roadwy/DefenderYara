
rule Trojan_Win32_Farfli_MAZ_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 45 e0 8b 0d 90 01 04 89 4d e4 8b 15 90 01 04 89 55 e8 a1 90 01 04 89 45 ec 8a 0d 90 01 04 88 4d f0 8d 55 e0 52 e8 90 01 04 83 c4 04 50 68 90 00 } //01 00 
		$a_01_1 = {4b 79 64 68 48 78 38 36 63 32 45 6d 49 69 42 44 } //01 00  KydhHx86c2EmIiBD
		$a_01_2 = {38 76 54 32 43 51 59 4c 43 7a 6f 2d } //01 00  8vT2CQYLCzo-
		$a_01_3 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //00 00  CreateToolhelp32Snapshot
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Farfli_MAZ_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.MAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {cf d7 b8 5e e4 d6 96 1b be 1a 0e d7 ea 78 fc 75 ca be b7 97 82 74 7f 33 c7 c7 b9 b7 82 d3 96 22 } //03 00 
		$a_01_1 = {3f 68 c9 6e 15 0e e6 5a 35 db d0 a8 78 5b 42 c3 e2 d6 3a 72 cf df 7f 5a f1 c8 30 1f a8 e4 e5 3a } //03 00 
		$a_01_2 = {4d 00 79 00 50 00 6c 00 61 00 79 00 65 00 72 00 20 00 46 00 6f 00 72 00 20 00 4d 00 79 00 20 00 4c 00 6f 00 76 00 65 00 72 00 } //01 00  MyPlayer For My Lover
		$a_01_3 = {40 2e 74 68 65 6d 69 64 61 } //00 00  @.themida
	condition:
		any of ($a_*)
 
}