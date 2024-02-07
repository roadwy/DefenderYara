
rule Trojan_Win32_Ursnif_AA_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 6f 77 61 72 64 79 65 61 72 5c 53 68 6f 75 6c 64 6f 6e 5c 73 75 72 65 53 75 6d 6d 65 72 5c 43 72 65 61 74 65 73 69 6e 67 6c 65 5c 61 6c 6c 6f 77 74 6f 42 79 2e 70 64 62 } //00 00  Towardyear\Shouldon\sureSummer\Createsingle\allowtoBy.pdb
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_AA_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 54 24 10 03 ee 13 f9 81 7c 24 18 90 01 04 8b 0d 68 74 57 00 8d b4 11 cc f4 ff ff 89 2d 40 80 56 00 89 3d 44 80 56 00 8b 0e 75 10 2b 05 04 80 56 00 90 00 } //01 00 
		$a_02_1 = {8b 7c 24 20 8d 83 90 01 04 03 c1 89 44 24 1c 0f b6 c6 8b 3f 66 6b c8 15 8b 44 24 24 2b 44 24 1c 83 c0 41 03 c6 66 03 4c 24 12 66 89 0d 90 01 04 89 44 24 18 81 fb 1b 69 81 25 75 90 00 } //01 00 
		$a_02_2 = {8d 44 30 04 8a d0 80 c2 04 66 03 fd 8b 2b 02 ca 66 89 3d 90 01 04 88 0d 90 01 04 81 fe 90 01 04 75 90 01 01 83 7c 24 24 00 75 90 00 } //01 00 
		$a_02_3 = {8d 44 28 f7 8b dd 81 c3 17 ff ff ff 83 d7 ff 66 a3 00 80 56 00 81 c1 30 ce 16 01 89 0d 18 8c 57 00 89 0e a1 90 01 03 00 90 00 } //01 00 
		$a_02_4 = {8b 74 24 20 81 c7 90 01 04 0f b6 d2 89 54 24 20 8b 54 24 14 83 7c 24 20 fe 0f b6 d2 89 54 24 14 0f b6 c0 0f 42 d0 89 3e 89 54 24 14 83 c6 04 8a 35 90 01 04 0f b6 c6 48 88 15 90 01 04 ff 4c 24 28 90 00 } //01 00 
		$a_02_5 = {8d 4c 10 a0 66 01 0d 90 01 04 81 c5 90 01 04 8d 44 30 04 89 2b 8b c8 66 39 3d 90 01 04 76 0f 0f b7 cf 2b c8 83 c1 04 90 00 } //00 00 
		$a_00_6 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}