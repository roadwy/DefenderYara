
rule Trojan_Win32_Redline_MF_MTB{
	meta:
		description = "Trojan:Win32/Redline.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 7d 08 f6 17 80 2f c2 fe 07 47 e2 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_MF_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {56 8d 45 f8 50 56 8d 85 90 01 04 50 56 56 68 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_MF_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {6b 75 d4 28 01 f2 03 4a 14 8b 55 dc 8b 75 d8 6b 7d d4 28 01 fe 03 56 0c 89 14 24 89 4c 24 04 89 44 24 08 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_MF_MTB_4{
	meta:
		description = "Trojan:Win32/Redline.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 55 f8 83 c2 02 89 55 f8 8b 45 fc 33 d2 b9 04 00 00 00 f7 f1 8b 45 10 0f b6 0c 10 8b 55 08 03 55 fc 0f b6 02 33 c1 8b 4d 08 03 4d fc 88 01 eb } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_2 = {47 65 74 46 6f 72 65 67 72 6f 75 6e 64 57 69 6e 64 6f 77 } //01 00  GetForegroundWindow
		$a_01_3 = {47 65 74 53 79 73 74 65 6d 49 6e 66 6f } //00 00  GetSystemInfo
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_MF_MTB_5{
	meta:
		description = "Trojan:Win32/Redline.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {83 c4 08 8b 45 08 03 45 d0 8a 08 80 c1 01 8b 55 08 03 55 d0 88 0a 8b 45 08 03 45 d0 8a 08 80 c1 01 8b 55 08 03 55 d0 88 0a 8b 45 08 03 45 d0 8a 08 80 c1 01 8b 55 08 03 55 d0 88 0a } //05 00 
		$a_01_1 = {8a 45 cc 88 45 cb 0f b6 4d cf 8b 55 08 03 55 d0 0f b6 02 03 c1 8b 4d 08 03 4d d0 88 01 8b 55 08 03 55 d0 8a 02 2c 01 8b 4d 08 03 4d d0 88 01 8b 55 08 03 55 d0 0f b6 02 83 e8 02 8b 4d 08 03 4d d0 88 01 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_MF_MTB_6{
	meta:
		description = "Trojan:Win32/Redline.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {56 33 3d 00 56 33 3d 00 56 33 3d 00 56 33 3d 03 56 33 3d 00 56 33 3d 1e 56 33 3d 32 56 33 3d 00 56 33 3d 00 56 33 3d 01 56 33 3d 04 56 33 3d 02 56 33 3d 00 56 33 3d 00 56 33 3d 00 56 33 3d } //02 00 
		$a_01_1 = {55 00 6e 00 6d 00 65 00 72 00 63 00 69 00 66 00 75 00 6c 00 2e 00 65 00 78 00 65 00 } //02 00  Unmerciful.exe
		$a_01_2 = {2e 31 32 38 78 65 71 32 } //02 00  .128xeq2
		$a_01_3 = {50 00 6c 00 65 00 61 00 73 00 65 00 2c 00 20 00 63 00 6f 00 6e 00 74 00 61 00 63 00 74 00 20 00 79 00 6f 00 75 00 72 00 73 00 69 00 74 00 65 00 40 00 79 00 6f 00 75 00 72 00 73 00 69 00 74 00 65 00 2e 00 63 00 6f 00 6d 00 2e 00 20 00 54 00 68 00 61 00 6e 00 6b 00 20 00 79 00 6f 00 75 00 21 00 } //00 00  Please, contact yoursite@yoursite.com. Thank you!
	condition:
		any of ($a_*)
 
}