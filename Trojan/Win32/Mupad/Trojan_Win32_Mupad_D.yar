
rule Trojan_Win32_Mupad_D{
	meta:
		description = "Trojan:Win32/Mupad.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 89 45 f6 c7 45 e4 00 00 00 00 c7 45 cc 00 00 00 00 8b 4d b4 89 4d b8 ba 90 01 03 00 85 d2 0f 84 90 01 02 00 00 83 7d b8 00 0f 84 90 01 02 00 00 b8 90 01 03 00 85 c0 0f 84 90 01 01 00 00 00 90 00 } //01 00 
		$a_03_1 = {6a 00 ff 15 90 01 02 40 00 6a 00 ff 15 90 01 02 40 00 83 f8 23 74 90 01 01 8b 90 01 01 c8 90 00 } //01 00 
		$a_03_2 = {6a 00 ff 15 90 01 02 40 00 85 c0 75 10 c7 45 c8 ff ff ff ff b9 40 00 00 00 51 ff 75 c4 ba 00 13 00 00 52 6a 00 b8 00 00 00 00 40 83 7d b8 42 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Mupad_D_2{
	meta:
		description = "Trojan:Win32/Mupad.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {3a 2f 2f 66 65 6c 6c 6f 77 72 61 74 31 32 35 2e 67 64 6e 2f 69 6e 64 65 78 2e 68 74 6d } //02 00  ://fellowrat125.gdn/index.htm
		$a_00_1 = {2f 2f 70 65 72 66 65 63 74 6c 79 62 65 6e 65 61 74 68 2e 67 64 6e 2f 69 6e 64 65 78 2e 68 74 6d } //02 00  //perfectlybeneath.gdn/index.htm
		$a_00_2 = {2f 2f 72 65 6d 61 69 6e 66 72 61 6d 65 2e 67 64 6e 2f 69 6e 64 65 78 2e 68 74 6d } //02 00  //remainframe.gdn/index.htm
		$a_00_3 = {63 72 79 70 74 3d 39 33 32 37 3b 67 2e 6c 69 63 65 6e 63 65 76 69 6f 6c 65 74 2e 67 64 6e } //02 00  crypt=9327;g.licenceviolet.gdn
		$a_02_4 = {70 72 6f 74 6f 63 6f 6c 3d 76 35 90 02 08 26 65 68 3d 90 02 08 26 76 3d 90 02 08 6d 69 64 3d 90 00 } //00 00 
		$a_00_5 = {78 e3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Mupad_D_3{
	meta:
		description = "Trojan:Win32/Mupad.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 45 e4 00 00 00 00 c7 45 cc 00 00 00 00 8b 4d b4 89 4d b8 ba 90 01 03 00 85 d2 0f 84 90 01 02 00 00 83 7d b8 00 0f 84 90 01 02 00 00 b8 90 01 03 00 85 c0 0f 84 90 01 01 00 00 00 90 00 } //01 00 
		$a_03_1 = {89 45 c0 6a 00 ff 15 90 01 02 40 00 6a 00 ff 15 90 01 02 40 00 83 f8 23 74 08 6a 00 ff 15 90 01 02 40 00 8b 55 c8 89 15 90 01 02 4c 00 6a 00 90 00 } //01 00 
		$a_01_2 = {85 c0 75 10 c7 45 c8 ff ff ff ff b9 40 00 00 00 51 ff 75 c4 b9 70 13 00 00 51 b9 00 00 00 00 51 83 7d b8 42 } //01 00 
		$a_03_3 = {6a 0a ff 15 90 01 02 40 00 6a 00 ff 15 90 01 02 40 00 85 c0 75 90 01 01 a1 90 01 02 40 00 89 45 b8 8b 4d b8 ff d1 a3 90 01 02 4c 00 c7 45 b4 0c 00 00 00 90 00 } //00 00 
		$a_00_4 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}