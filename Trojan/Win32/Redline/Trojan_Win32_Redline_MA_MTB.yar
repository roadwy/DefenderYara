
rule Trojan_Win32_Redline_MA_MTB{
	meta:
		description = "Trojan:Win32/Redline.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 89 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f6 17 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 2f ?? 80 07 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f6 2f 47 e2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Redline_MA_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 dc 99 b9 ?? ?? ?? ?? f7 f9 8b 45 08 0f be 0c 10 69 c9 ?? ?? ?? ?? 83 e1 ?? 8b 55 0c 03 55 dc 0f b6 02 33 c1 8b 4d 0c 03 4d dc 88 01 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Redline_MA_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {89 45 fc b8 d6 38 00 00 01 45 fc 8b 45 08 8b 4d fc 8a 0c 01 8b 15 ?? ?? ?? ?? 88 0c 02 c9 c2 } //1
		$a_03_1 = {8b 45 d8 01 45 f0 8d 04 3e 89 45 f4 8b c7 c1 e8 05 83 3d ?? ?? ?? ?? 1b 89 45 0c 75 ?? 33 c0 50 50 50 ff 15 } //1
		$a_01_2 = {55 6e 6c 6f 63 6b 46 69 6c 65 } //1 UnlockFile
		$a_01_3 = {44 65 6c 65 74 65 46 69 6c 65 57 } //1 DeleteFileW
		$a_01_4 = {47 65 74 44 69 73 6b 46 72 65 65 53 70 61 63 65 45 78 41 } //1 GetDiskFreeSpaceExA
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Redline_MA_MTB_4{
	meta:
		description = "Trojan:Win32/Redline.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 06 00 00 "
		
	strings :
		$a_01_0 = {48 00 41 00 54 00 4f 00 54 00 41 00 47 00 } //5 HATOTAG
		$a_01_1 = {4a 00 45 00 59 00 41 00 47 00 4f 00 51 00 } //5 JEYAGOQ
		$a_01_2 = {53 00 4f 00 42 00 45 00 48 00 41 00 56 00 4f 00 42 00 41 00 } //5 SOBEHAVOBA
		$a_01_3 = {72 65 72 6f 71 20 6e 6f 67 69 6e 65 74 69 20 66 6f 70 61 78 61 20 66 61 68 20 6c 61 6e 61 66 20 76 65 63 61 62 } //5 reroq nogineti fopaxa fah lanaf vecab
		$a_01_4 = {5c 68 65 64 6f 2e 70 64 62 } //1 \hedo.pdb
		$a_01_5 = {41 62 6f 72 74 53 79 73 74 65 6d 53 68 75 74 64 6f 77 6e 41 } //1 AbortSystemShutdownA
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=22
 
}