
rule TrojanDownloader_Win32_Banload_OL{
	meta:
		description = "TrojanDownloader:Win32/Banload.OL,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 0e 8b 1f 38 d9 75 41 4a 74 17 38 fd 75 3a 4a 74 10 81 e3 00 00 ff 00 81 e1 00 00 ff 00 39 d9 75 27 } //4
		$a_01_1 = {4c 54 39 47 34 50 4e 30 6a 7c 63 46 4d 5a 69 37 49 4b 78 7a 6d 71 65 79 4a 62 36 59 75 32 58 72 66 31 45 48 76 61 74 6b 70 4f 6c 77 41 35 38 44 57 6e 68 53 43 51 52 6f 56 33 64 42 } //2 LT9G4PN0j|cFMZi7IKxzmqeyJb6Yu2Xrf1EHvatkpOlwA58DWnhSCQRoV3dB
		$a_01_2 = {30 7a 7a 37 3a 2f 2f } //2 0zz7://
		$a_02_3 = {73 79 73 74 65 6d 33 32 5c [0-10] 2e 6a 70 67 } //2
		$a_01_4 = {30 69 7a 4d 4c 6a 46 2e 4b 6d } //2 0izMLjF.Km
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_02_3  & 1)*2+(#a_01_4  & 1)*2) >=8
 
}