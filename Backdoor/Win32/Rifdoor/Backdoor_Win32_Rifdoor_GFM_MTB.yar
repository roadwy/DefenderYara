
rule Backdoor_Win32_Rifdoor_GFM_MTB{
	meta:
		description = "Backdoor:Win32/Rifdoor.GFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b ce 8b b5 90 01 04 c1 e9 18 c1 ea 10 22 ca 8a 95 90 01 04 32 d9 8b 8d 90 01 04 22 d1 32 da 8d 94 3d 90 01 04 32 1c 16 8d 34 85 90 01 04 33 f0 03 f6 33 f0 32 d8 83 e6 f0 c1 e0 04 33 f0 c1 e1 18 0b 8d 90 01 04 c1 e6 14 0b b5 90 01 04 47 88 1a 89 b5 90 01 04 8b c1 3b bd 90 01 04 0f 8c 90 00 } //01 00 
		$a_01_1 = {55 52 4c 4f 70 65 6e 42 6c 6f 63 6b 69 6e 67 53 74 72 65 61 6d } //01 00 
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00 
		$a_01_3 = {5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 55 70 64 61 74 65 5c 57 77 61 6e 53 76 63 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}