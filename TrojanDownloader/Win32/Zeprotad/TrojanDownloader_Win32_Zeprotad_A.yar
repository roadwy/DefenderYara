
rule TrojanDownloader_Win32_Zeprotad_A{
	meta:
		description = "TrojanDownloader:Win32/Zeprotad.A,SIGNATURE_TYPE_PEHSTR_EXT,16 00 0b 00 0b 00 00 0a 00 "
		
	strings :
		$a_03_0 = {75 57 56 8d 85 90 01 02 ff ff 68 00 80 00 00 50 e8 90 01 02 00 00 83 c4 90 01 01 3b c7 89 45 0c 7d 07 33 c0 e9 90 01 01 00 00 00 6a 02 57 50 e8 90 01 02 00 00 83 c4 90 01 01 3d 88 13 00 00 ff 75 0c 7f 90 00 } //05 00 
		$a_01_1 = {99 b9 28 23 00 00 f7 f9 8d 85 a8 fe ff ff 52 50 8d 85 a8 fe ff ff 68 e0 40 41 00 } //05 00 
		$a_03_2 = {83 f8 07 0f 87 df 01 00 00 ff 24 85 90 01 02 40 00 8d 45 d8 68 a0 41 41 00 90 00 } //01 00 
		$a_00_3 = {70 30 30 2e 64 61 74 3f 69 64 3d } //01 00  p00.dat?id=
		$a_00_4 = {24 77 69 6e 64 6f 77 73 5c 73 6f 75 6e 64 6c 69 62 2e 65 78 65 00 } //01 00 
		$a_00_5 = {24 77 69 6e 64 6f 77 73 5c 73 6f 75 6e 64 67 75 69 2e 65 78 65 00 } //01 00 
		$a_00_6 = {24 77 69 6e 64 6f 77 73 5c 66 6c 61 73 68 67 61 6d 65 2e 65 78 65 00 } //01 00 
		$a_00_7 = {24 70 72 6f 67 72 61 6d 6d 69 00 } //01 00 
		$a_00_8 = {24 73 79 73 74 65 6d 5c 6e 65 74 73 68 2e 65 78 65 00 } //01 00 
		$a_00_9 = {2f 25 73 3f 69 64 3d 25 69 26 75 3d 25 73 26 76 3d 30 00 } //01 00 
		$a_00_10 = {73 65 74 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d 20 70 72 6f 67 72 61 6d 20 3d 20 22 25 73 22 20 6e 61 6d 65 20 3d 20 22 73 65 63 75 72 65 73 79 73 74 64 22 20 6d 6f 64 65 20 3d 20 45 4e 41 42 4c 45 20 73 63 6f 70 65 20 3d 20 41 4c 4c 20 70 72 6f 66 69 6c 65 20 3d 20 41 4c 4c } //00 00  set allowedprogram program = "%s" name = "securesystd" mode = ENABLE scope = ALL profile = ALL
	condition:
		any of ($a_*)
 
}