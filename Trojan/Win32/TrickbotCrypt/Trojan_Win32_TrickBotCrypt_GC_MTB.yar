
rule Trojan_Win32_TrickBotCrypt_GC_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 01 8b 4d 0c 0f b6 14 11 33 d0 a1 90 01 04 0f af 05 90 01 04 8b 0d 90 01 04 0f af 0d 90 01 04 8b 35 90 01 04 0f af 35 90 01 04 8b 3d 90 01 04 0f af 3d 90 01 04 0f af 3d 90 01 04 03 7d f4 03 fe 2b 3d 90 01 04 2b 3d 90 01 04 03 f9 2b 3d 90 01 04 2b 3d 90 01 04 2b 3d 90 01 04 2b f8 8b 45 0c 88 14 38 90 00 } //1
		$a_01_1 = {67 56 74 23 28 50 71 42 50 52 55 69 41 4d 50 65 4c 58 4e 4f 4b 44 63 63 68 61 44 64 6c 68 6d 34 26 6f 56 34 45 51 55 33 42 26 2b 59 74 63 5f 47 72 69 26 48 46 3f 2a 43 6a 4e 55 67 70 6e 77 44 24 6c 5e 73 6b 79 } //1 gVt#(PqBPRUiAMPeLXNOKDcchaDdlhm4&oV4EQU3B&+Ytc_Gri&HF?*CjNUgpnwD$l^sky
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}