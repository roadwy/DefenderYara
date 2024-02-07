
rule Trojan_Win32_Emotet_DA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 02 00 00 0a 00 "
		
	strings :
		$a_00_0 = {89 44 24 20 b8 02 00 00 00 2b c6 89 6c 24 14 2b c1 8d 6a fd 0f af c6 0f af ef 0f af d9 03 c5 8b 6c 24 34 83 c4 04 8d 04 40 2b c3 2b c2 } //03 00 
		$a_01_1 = {7a 64 71 31 31 28 7a 74 67 59 45 7a 5f 42 4e 78 57 78 3c 68 57 4f 72 4e 41 42 34 56 34 63 73 75 50 48 42 67 33 76 79 } //00 00  zdq11(ztgYEz_BNxWx<hWOrNAB4V4csuPHBg3vy
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_DA_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 89 e5 56 50 8a 45 14 8b 4d 10 8b 55 0c 8b 75 08 b4 90 01 01 c6 45 fb 90 01 01 2a 65 fb 30 e0 02 04 0a 88 04 0e 83 c4 04 5e 5d c3 90 00 } //01 00 
		$a_03_1 = {8a 1c 11 0f b6 fb 8b 4d d0 01 f9 89 c8 89 55 c8 99 f7 fe 8b 4d e0 8a 3c 11 8b 75 f0 81 f6 90 01 04 89 55 c4 8b 55 c8 88 3c 11 8b 55 c4 88 1c 11 8b 4d f0 8b 55 e0 8b 5d c8 0f b6 14 1a 01 fa 81 c1 90 01 04 21 ca 8b 4d e0 8a 0c 11 8b 55 e8 8b 7d cc 32 0c 3a 8b 55 e4 88 0c 3a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}