
rule Trojan_Win32_GandCrab_KDV_MTB{
	meta:
		description = "Trojan:Win32/GandCrab.KDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {8b d3 c1 ea 05 03 54 24 1c 8b c3 c1 e0 04 03 44 24 20 8d 0c 2b 33 d0 33 d1 2b fa 81 fe 61 0e 00 00 73 } //02 00 
		$a_00_1 = {8b c6 c1 e8 05 03 45 e4 8b ce c1 e1 04 03 4d e0 33 c1 8d 0c 33 33 c1 2b f8 81 7d f0 1d 1e 00 00 73 } //02 00 
		$a_02_2 = {8b 00 40 8b 8d 90 01 01 fb ff ff 89 01 8b 4d fc 33 cd e8 90 01 04 8b e5 5d c3 90 09 06 00 8b 85 90 01 01 fb ff ff 90 00 } //02 00 
		$a_02_3 = {8b ff 8b ca a3 90 01 04 33 c1 8b ff c7 05 90 01 04 00 00 00 00 8b ff 01 05 90 01 04 8b ff a1 90 01 04 8b 0d 90 01 04 89 08 90 09 05 00 a1 90 00 } //02 00 
		$a_00_4 = {63 47 77 4c 76 41 7d 24 24 57 4e 4e 2a 68 50 35 75 56 35 70 4c 63 50 78 61 68 77 4d 4c 56 4b 55 44 50 40 25 4c 6e 66 47 47 24 57 6e 48 6f 70 76 6a 24 68 64 78 33 51 31 66 54 64 6b 43 72 23 51 } //00 00  cGwLvA}$$WNN*hP5uV5pLcPxahwMLVKUDP@%LnfGG$WnHopvj$hdx3Q1fTdkCr#Q
	condition:
		any of ($a_*)
 
}