
rule Backdoor_Win32_Moudoor_A{
	meta:
		description = "Backdoor:Win32/Moudoor.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {70 69 6e 67 20 6c 6f 63 61 6c 68 6f 73 74 20 2d 6e 20 90 02 02 20 26 20 64 65 6c 20 22 25 73 22 90 00 } //01 00 
		$a_03_1 = {c3 33 c9 85 ff 76 1e 8b c1 bd 06 00 00 00 99 f7 fd 8a 04 31 80 c2 90 01 01 32 c2 88 04 31 41 3b cf 72 e6 8b 6c 24 90 01 01 8d 44 24 90 01 01 6a 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Moudoor_A_2{
	meta:
		description = "Backdoor:Win32/Moudoor.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 55 f8 83 c2 01 89 55 f8 8b 45 f8 3b 45 f4 7d 2e 8b 4d fc 03 4d f8 0f be 11 81 ea 90 01 01 00 00 00 8b 45 fc 03 45 f8 88 10 90 90 8b 4d fc 03 4d f8 0f be 11 83 f2 90 01 01 8b 45 fc 03 45 f8 88 10 90 00 } //02 00 
		$a_03_1 = {8b 55 fc 83 c2 01 89 55 fc 8b 45 fc 3b 45 f8 73 26 8b 4d 90 01 01 03 4d fc 33 d2 8a 11 8b ca 8b 45 fc 99 be 90 01 01 00 00 00 f7 fe 83 c2 90 01 01 33 ca 8b 55 90 01 01 03 55 fc 88 0a eb c9 90 00 } //01 00 
		$a_01_2 = {55 70 64 61 74 65 57 69 6e 64 6f 77 00 00 00 00 61 75 74 6f 2e 64 61 74 } //01 00 
		$a_01_3 = {68 6f 73 74 2e 65 78 65 00 4d 69 63 72 6f 73 6f 66 74 20 55 70 64 61 74 65 00 } //00 00  潨瑳攮數䴀捩潲潳瑦唠摰瑡e
	condition:
		any of ($a_*)
 
}