
rule Trojan_Win32_EyeStye_N{
	meta:
		description = "Trojan:Win32/EyeStye.N,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c7 45 f8 d9 09 00 00 8b 55 f0 81 f2 00 00 00 99 89 15 90 01 02 42 00 8b 05 90 01 02 43 00 f7 d0 05 90 01 02 00 00 c1 e8 90 01 01 89 45 ec 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_EyeStye_N_2{
	meta:
		description = "Trojan:Win32/EyeStye.N,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {c7 45 b8 5c 3f 3f 5c c6 45 bc 00 89 85 54 ff ff ff e8 00 00 00 00 58 89 45 f8 8b 45 f8 8b d0 81 e2 ff 0f 00 00 33 c9 2b c2 41 05 20 0b 00 00 81 38 21 45 59 45 8b f8 } //01 00 
		$a_03_1 = {51 68 65 24 58 6a 6a 03 e8 90 01 03 ff 59 90 00 } //01 00 
		$a_01_2 = {83 7d 08 03 75 2b 8b 06 3d 6e 74 64 6c 74 07 3d 4e 54 44 4c 75 1b 64 a1 30 00 00 00 8b 40 0c } //01 00 
		$a_03_3 = {3d 33 8a 04 43 0f 84 90 01 04 39 7d e0 74 14 3d 72 09 0a 49 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}