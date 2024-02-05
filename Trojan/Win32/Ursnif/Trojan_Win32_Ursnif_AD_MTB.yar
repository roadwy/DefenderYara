
rule Trojan_Win32_Ursnif_AD_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 44 24 14 8b 0e 8d 7c 07 bc 8b c2 0f b7 15 90 01 03 00 2b c3 05 90 01 04 8b e8 69 ed 90 01 03 00 81 c1 90 01 04 89 0e 03 d5 83 c6 04 ff 4c 24 10 75 b4 90 00 } //01 00 
		$a_02_1 = {03 ca 81 f9 90 01 04 75 0d 2b d3 83 ea 90 01 01 69 d2 90 01 04 03 d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_AD_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 73 61 74 5c 53 65 63 74 69 6f 6e 5c 73 74 6f 6f 64 5c 63 6f 75 6e 74 72 79 5c 73 74 72 6f 6e 67 5c 73 65 67 6d 65 6e 74 5c 46 65 6c 6c 5c 6d 6f 73 74 63 68 69 6c 64 2e 70 64 62 } //01 00 
		$a_01_1 = {69 66 20 65 78 69 73 74 73 20 28 73 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 64 62 6f 2e 73 79 73 6f 62 6a 65 63 74 73 20 77 68 65 72 65 20 69 64 20 3d 20 6f 62 6a 65 63 74 5f 69 64 28 4e 27 5b 64 62 6f 5d 2e 5b 50 72 63 5f 51 75 65 72 79 4c 6f 61 64 54 65 73 74 52 65 71 75 65 73 74 53 75 6d 6d 61 72 79 5d 27 29 20 61 6e 64 20 4f 42 4a 45 43 54 50 52 4f 50 45 52 54 59 28 69 64 2c 20 4e 27 49 73 50 72 6f 63 65 64 75 72 65 27 29 20 3d 20 31 29 } //01 00 
		$a_01_2 = {75 67 6f 65 6f 64 54 5d 74 6e 73 35 61 4c 6e 52 61 20 4e 20 75 6d 4c 75 6e 20 5d 6c 74 20 63 65 72 6f 67 50 20 20 6e 20 6d 54 54 6f 52 20 50 20 6c 45 73 74 64 4f 41 5d 4b 6f 5d 45 74 54 46 29 73 61 20 43 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_AD_MTB_3{
	meta:
		description = "Trojan:Win32/Ursnif.AD!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {80 c2 20 c1 c1 07 0f be c2 33 c8 f7 d1 41 46 47 8a 16 84 d2 } //0a 00 
		$a_01_1 = {80 84 1d 1e ff ff ff f6 43 83 fb 0a 72 f2 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_AD_MTB_4{
	meta:
		description = "Trojan:Win32/Ursnif.AD!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {71 6c 6a 6e 6f 69 69 6e 5a 54 53 72 } //01 00 
		$a_01_1 = {39 37 36 3b 34 33 32 33 34 32 32 33 3f 3d 3d 33 4e 4b 4b 33 68 63 62 40 78 72 70 4d 6e 68 67 4f 6e 68 } //01 00 
		$a_01_2 = {39 38 37 56 3a 39 39 56 3c 3b 3b 56 41 3f 3f 56 45 44 43 56 47 47 46 56 48 48 47 51 45 44 44 09 } //01 00 
		$a_01_3 = {35 34 34 6b 30 2f 2f 4f 50 4c 4b 52 6e 67 66 } //01 00 
		$a_01_4 = {28 27 27 45 2f 2d 2d 28 4e 49 47 2e 4e 49 47 2e 4e 49 47 2e 4e 49 48 2e 4e 49 48 2e 4e 49 48 2e 4e 49 48 2e 3c 39 39 2c 27 27 27 29 2f 2f 2f 4b 3a 39 39 54 23 23 23 0a } //00 00 
	condition:
		any of ($a_*)
 
}