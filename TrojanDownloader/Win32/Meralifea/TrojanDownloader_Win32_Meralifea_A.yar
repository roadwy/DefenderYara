
rule TrojanDownloader_Win32_Meralifea_A{
	meta:
		description = "TrojanDownloader:Win32/Meralifea.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0c 00 00 02 00 "
		
	strings :
		$a_03_0 = {68 7c 4a 00 00 68 70 4a 00 00 c7 45 90 01 01 53 29 00 00 c7 45 90 01 01 6f 29 00 00 c7 45 90 01 01 61 29 00 00 90 00 } //02 00 
		$a_01_1 = {83 f8 7a 89 44 24 14 74 05 83 f8 6f 75 28 56 6a 00 ff d7 50 ff d5 } //01 00 
		$a_00_2 = {49 4e 53 54 41 4c 4c 5f 43 49 44 } //01 00  INSTALL_CID
		$a_00_3 = {49 4e 53 54 41 4c 4c 5f 53 49 44 } //01 00  INSTALL_SID
		$a_00_4 = {49 4e 53 54 41 4c 4c 5f 53 4f 55 52 43 45 } //01 00  INSTALL_SOURCE
		$a_00_5 = {26 73 69 64 3d 25 75 } //01 00  &sid=%u
		$a_00_6 = {26 73 7a 3d } //01 00  &sz=
		$a_00_7 = {6f 73 3d 25 64 26 61 72 3d 25 64 } //03 00  os=%d&ar=%d
		$a_00_8 = {73 6c 74 70 3a 2f 2f 73 65 74 75 70 2e 67 6f 68 75 62 2e 6f 6e 6c 69 6e 65 3a 31 31 30 38 } //02 00  sltp://setup.gohub.online:1108
		$a_00_9 = {2f 73 65 74 75 70 2e 62 69 6e 3f 69 64 3d 31 32 38 } //02 00  /setup.bin?id=128
		$a_80_10 = {5c 3f 3f 5c 4e 50 46 2d 7b 30 31 37 39 41 43 34 35 2d 43 32 32 36 2d 34 38 65 33 2d 41 32 30 35 2d 44 43 41 37 39 43 38 32 34 30 35 31 7d } //\??\NPF-{0179AC45-C226-48e3-A205-DCA79C824051}  01 00 
		$a_80_11 = {5c 2e 5c 58 3a } //\.\X:  00 00 
		$a_00_12 = {5d 04 00 00 8b bb } //03 80 
	condition:
		any of ($a_*)
 
}