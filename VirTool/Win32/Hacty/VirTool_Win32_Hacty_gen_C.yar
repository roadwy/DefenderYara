
rule VirTool_Win32_Hacty_gen_C{
	meta:
		description = "VirTool:Win32/Hacty.gen!C,SIGNATURE_TYPE_PEHSTR,20 00 1e 00 0d 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b c7 8d 50 01 8a 08 40 84 c9 75 f9 2b c2 89 45 2c 74 61 8b 43 3c d1 e8 50 57 ff 75 fc ff 15 } //05 00 
		$a_01_1 = {8b 4b 3c d1 e9 3b c1 74 10 81 c7 00 01 00 00 81 ff 08 3a 01 00 7c c6 eb 38 83 7d 24 00 74 13 3b 5d 1c 75 09 c7 45 30 06 00 00 80 eb 24 } //05 00 
		$a_01_2 = {83 26 00 eb 1f 8b 03 8b 4d 1c 2b c8 2b cb 03 4d 20 8d 34 18 8b c1 c1 e9 02 8b fb f3 a5 8b c8 83 e1 03 f3 a4 8b f3 03 1b 83 7d 24 00 0f 84 12 } //05 00 
		$a_01_3 = {8b 45 18 8b 40 04 6a 14 59 f7 f1 83 65 1c 00 85 c0 7e 7a 8d 48 ff 89 4d 20 8d 4b 14 89 4d 2c be } //05 00 
		$a_01_4 = {8b 3e 85 ff 74 54 33 c9 8a 6b 08 8a 4b 09 3b cf 74 0d 83 c6 04 81 } //05 00 
		$a_01_5 = {7c e3 eb 3b 8b 4d 20 39 4d 1c 74 2f 8b 75 2c 8b c8 2b 4d 1c 8b fb 49 8d 0c 89 c1 e1 02 8b d1 c1 e9 02 f3 a5 8b ca 83 e1 03 48 ff 4d 20 ff 4d 1c } //05 00 
		$a_01_6 = {85 c0 7c 65 83 7d 08 05 75 5f 8b 16 57 33 ff 85 d2 8b ce 74 4f 8d 0c 32 eb 4a be } //05 00 
		$a_01_7 = {8b 16 85 d2 74 2d 39 51 44 75 19 85 ff 74 0d 8b 11 85 d2 74 04 01 17 eb 03 83 27 00 8b 11 85 d2 74 0f 03 ca 83 c6 04 81 } //05 00 
		$a_01_8 = {7c d1 eb 02 33 c9 85 c9 74 12 8b 11 85 d2 8b f9 74 04 03 ca eb 02 33 c9 85 c9 75 b2 5f } //02 00 
		$a_01_9 = {5a 46 4a 5f 52 4f 4f 54 4b 49 54 } //01 00  ZFJ_ROOTKIT
		$a_01_10 = {5a 77 51 75 65 72 79 44 69 72 65 63 74 6f 72 79 46 69 6c 65 } //01 00  ZwQueryDirectoryFile
		$a_01_11 = {5a 77 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //01 00  ZwQuerySystemInformation
		$a_01_12 = {5a 77 44 65 76 69 63 65 49 6f 43 6f 6e 74 72 6f 6c 46 69 6c 65 } //00 00  ZwDeviceIoControlFile
	condition:
		any of ($a_*)
 
}