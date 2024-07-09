
rule Trojan_Win32_Redline_MG_MTB{
	meta:
		description = "Trojan:Win32/Redline.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 08 8b 55 f4 8b 45 08 01 d0 0f b6 55 e7 31 ca 88 10 83 45 f4 01 8b 45 f4 3b 45 0c 7c ac } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Redline_MG_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {99 bf 37 00 00 00 f7 ff 8b 45 08 0f be 14 10 6b d2 34 83 e2 13 83 e2 51 33 f2 03 ce 8b 45 0c 03 45 fc 88 08 0f be 4d fb 8b 55 0c 03 55 fc 0f be 02 2b c1 8b 4d 0c 03 4d fc 88 01 eb } //5
		$a_01_1 = {73 68 46 6c 65 45 6a 4f 42 66 52 32 4c 48 41 48 35 45 64 64 65 67 4b 68 4e 30 4f 34 6a 58 64 79 52 63 78 75 56 70 62 4c 32 69 31 48 73 57 75 6d 59 42 4d 51 43 43 35 50 58 6d 69 33 4c 6b 35 6b 35 } //2 shFleEjOBfR2LHAH5EddegKhN0O4jXdyRcxuVpbL2i1HsWumYBMQCC5PXmi3Lk5k5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}
rule Trojan_Win32_Redline_MG_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 05 00 00 "
		
	strings :
		$a_01_0 = {3b df 03 f1 e9 79 80 17 00 8b 0e 8b 56 04 f7 d1 c1 d8 dc f5 f7 d2 0f a4 d8 71 c0 ec 7e f5 0b ca 66 90 89 4e 04 66 0f b6 c1 9c 80 d4 2d 8f 06 c0 } //5
		$a_01_1 = {85 f5 33 c3 f9 f8 d1 c8 2d 56 0f b0 1c f8 35 61 45 9b 7f 48 f7 c6 2c 70 d2 5d 35 16 68 93 4b e9 ef 0c 15 00 8b 0e 36 8b 11 0f b7 c4 03 c0 89 16 } //5
		$a_01_2 = {e0 00 02 01 0b 01 0e 18 00 72 02 00 00 08 09 00 00 00 00 00 10 87 38 00 00 10 } //5
		$a_01_3 = {2e 76 6d 70 30 } //2 .vmp0
		$a_01_4 = {2e 76 6d 70 32 } //2 .vmp2
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=19
 
}
rule Trojan_Win32_Redline_MG_MTB_4{
	meta:
		description = "Trojan:Win32/Redline.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 "
		
	strings :
		$a_03_0 = {8b 55 f4 83 c2 01 89 55 f4 8b 45 f4 3b 45 10 73 ?? 8b 4d fc 03 4d f4 8b 55 f8 03 55 f4 8a 02 88 01 eb } //5
		$a_01_1 = {6d 75 67 6f 6b 61 74 65 72 69 70 61 79 61 73 6f 6a 65 6c 69 68 75 70 75 72 69 7a 61 72 75 6d 69 } //5 mugokateripayasojelihupurizarumi
		$a_01_2 = {51 75 65 72 79 44 6f 73 44 65 76 69 63 65 57 } //1 QueryDosDeviceW
		$a_01_3 = {47 65 74 44 69 73 6b 46 72 65 65 53 70 61 63 65 45 78 41 } //1 GetDiskFreeSpaceExA
		$a_01_4 = {44 65 62 75 67 53 65 74 50 72 6f 63 65 73 73 4b 69 6c 6c 4f 6e 45 78 69 74 } //1 DebugSetProcessKillOnExit
		$a_01_5 = {68 00 6f 00 74 00 6b 00 65 00 79 00 33 00 32 00 } //1 hotkey32
		$a_01_6 = {53 65 74 4d 61 69 6c 73 6c 6f 74 49 6e 66 6f } //1 SetMailslotInfo
		$a_01_7 = {43 72 65 61 74 65 4d 61 69 6c 73 6c 6f 74 41 } //1 CreateMailslotA
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=16
 
}