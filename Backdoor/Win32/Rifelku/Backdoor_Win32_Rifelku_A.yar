
rule Backdoor_Win32_Rifelku_A{
	meta:
		description = "Backdoor:Win32/Rifelku.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0a 00 00 01 00 "
		
	strings :
		$a_00_0 = {c1 ef 05 8b da c1 e3 04 33 fb 03 fa 8b d8 83 e3 03 8b 5c 9d ec 03 d8 33 fb 03 cf 2d 47 86 c8 61 } //01 00 
		$a_00_1 = {c1 ef 05 8b d9 c1 e3 04 33 fb 03 f9 8b d8 c1 eb 0b 83 e3 03 } //01 00 
		$a_00_2 = {c1 eb 18 32 1c 3e 89 55 e0 c1 ea 10 32 da 8b d1 c1 ea 18 32 da 8b 55 e0 c1 ea 08 32 da } //01 00 
		$a_01_3 = {2a 2a 44 6f 77 6e 6c 6f 61 64 20 53 75 63 63 2a 2a } //01 00 
		$a_01_4 = {2a 2a 44 6f 77 6e 6c 6f 61 64 20 46 61 69 6c 2a 2a } //01 00 
		$a_01_5 = {24 64 6f 77 6e 6c 6f 61 64 } //01 00 
		$a_01_6 = {73 65 63 2e 65 78 65 } //01 00 
		$a_01_7 = {24 64 6f 77 6e 6c 6f 61 64 65 78 65 63 } //01 00 
		$a_01_8 = {43 4d 44 3a 25 73 20 50 52 4f 43 45 53 53 45 44 20 41 54 20 25 64 2f 25 64 2f } //01 00 
		$a_01_9 = {73 6e 69 66 66 65 72 } //00 00 
		$a_00_10 = {5d 04 00 00 } //61 76 
	condition:
		any of ($a_*)
 
}