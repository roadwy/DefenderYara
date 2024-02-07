
rule TrojanDownloader_Win32_Cojopesh_B{
	meta:
		description = "TrojanDownloader:Win32/Cojopesh.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {83 f8 4d 0f 85 90 01 01 01 00 00 0f be 8d d8 ea ff ff 83 f9 5a 0f 85 90 01 01 01 00 00 83 7d 0c 00 0f 85 90 01 01 01 00 00 c6 85 90 01 02 ff ff 00 b9 40 00 00 00 33 c0 8d bd 90 01 02 ff ff f3 ab 66 ab aa c7 85 90 01 02 ff ff 44 00 00 00 90 00 } //01 00 
		$a_03_1 = {eb aa 8b 45 fc 8a 08 88 8d 90 01 02 ff ff 8b 55 fc 8a 42 01 88 85 90 01 02 ff ff 83 7d 0c 00 75 34 90 00 } //01 00 
		$a_03_2 = {68 10 27 00 00 ff 15 90 01 02 40 00 83 3d 90 01 02 40 00 00 74 13 68 80 8d 5b 00 ff 15 90 01 02 40 00 6a 00 ff 15 90 01 02 40 00 eb 8a 68 00 e0 2e 00 ff 15 90 00 } //01 00 
		$a_01_3 = {41 53 4d 44 4a 48 47 31 37 36 45 52 54 44 55 59 54 51 55 57 59 45 54 44 55 59 54 31 38 32 37 33 36 38 45 38 39 31 45 32 59 49 } //01 00  ASMDJHG176ERTDUYTQUWYETDUYT1827368E891E2YI
		$a_01_4 = {39 38 37 39 38 31 32 33 38 37 36 } //00 00  98798123876
	condition:
		any of ($a_*)
 
}