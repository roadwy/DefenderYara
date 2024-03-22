
rule TrojanDownloader_O97M_Donoff_DR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.DR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {67 69 74 68 75 62 2e 63 6f 6d 2f 44 33 56 49 35 48 34 2f 46 4c 41 4d 45 53 2f 62 6c 6f 62 2f 6d 61 69 6e 2f 44 61 74 61 25 32 30 45 78 66 69 6c 74 72 61 74 6f 72 2e 65 78 65 22 90 0a 44 00 22 68 74 74 70 73 3a 2f 2f 90 00 } //01 00 
		$a_01_1 = {44 65 73 6b 74 6f 70 22 20 26 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 50 61 74 68 53 65 70 61 72 61 74 6f 72 20 26 } //01 00  Desktop" & Application.PathSeparator &
		$a_01_2 = {66 69 6c 65 2e 65 78 65 22 } //01 00  file.exe"
		$a_01_3 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 6d 79 55 52 4c 2c 20 46 61 6c 73 65 } //01 00  .Open "GET", myURL, False
		$a_01_4 = {57 69 6e 48 74 74 70 52 65 71 2e 53 65 6e 64 } //01 00  WinHttpReq.Send
		$a_01_5 = {53 68 65 6c 6c 28 22 43 3a 5c 57 49 4e 44 4f 57 53 5c 4e 4f 54 45 50 41 44 2e 45 58 45 22 2c 20 31 29 } //00 00  Shell("C:\WINDOWS\NOTEPAD.EXE", 1)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_DR_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.DR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {7a 66 6c 6f 78 75 61 63 7a 69 75 79 76 66 67 67 63 66 69 68 6c 68 72 68 77 77 6e 6a 70 70 6d 69 6c 6d 69 71 65 65 6e 7a 7a 6c 6e 6e 6a 65 7a 6b 6a 6f 6c 6b 72 63 69 72 70 65 69 6c 69 78 64 61 6f 6d 66 62 75 67 64 7a 68 66 76 6d 6b 74 6d 6e 69 69 71 71 6b 69 72 76 6b 72 6a 6d 78 79 73 6d 75 67 6a 6b } //01 00  zfloxuacziuyvfggcfihlhrhwwnjppmilmiqeenzzlnnjezkjolkrcirpeilixdaomfbugdzhfvmktmniiqqkirvkrjmxysmugjk
		$a_01_1 = {2d 65 73 71 62 66 61 66 67 61 69 61 61 67 61 63 67 61 74 67 62 6c 61 68 63 61 6c 71 62 70 61 67 69 61 61 67 62 6c 61 67 6d 61 64 61 61 67 61 65 34 61 7a 71 62 30 61 63 34 61 76 77 62 6c 61 67 69 61 71 77 62 73 61 67 6b 61 7a 71 62 75 61 68 71 61 6b 71 61 75 61 65 71 61 62 77 62 33 61 67 34 61 62 61 62 76 61 67 65 61 7a 61 62 74 61 68 71 61 63 67 62 70 61 67 34 61 7a 77 61 75 61 65 6b 61 62 67 62 32 61 67 38 61 61 77 62 6c 61 63 67 } //01 00  -esqbfafgaiaagacgatgblahcalqbpagiaagblagmadaagae4azqb0ac4avwblagiaqwbsagkazqbuahqakqauaeqabwb3ag4ababvageazabtahqacgbpag4azwauaekabgb2ag8aawblacg
		$a_01_2 = {6a 61 7a 79 72 77 71 79 6b 68 7a 72 68 69 79 70 79 66 71 71 66 64 78 64 6a 66 7a 6a 63 7a 6c 62 72 75 73 77 70 76 6e 63 71 63 75 66 6b 68 6c 73 7a 69 65 64 77 79 6e 72 6a 69 67 68 6f 70 61 62 76 63 71 70 63 72 71 70 67 74 71 6b 75 75 78 77 63 69 62 66 6a 75 76 62 69 69 73 65 69 6f 66 6a 73 6f 6b 63 68 6f 6a 68 69 7a 62 76 79 69 62 70 64 66 78 71 64 76 69 6a 6d 65 77 66 6c 62 77 79 6b 70 75 62 68 6d 64 64 6b 69 79 76 70 6d 6c } //00 00  jazyrwqykhzrhiypyfqqfdxdjfzjczlbruswpvncqcufkhlsziedwynrjighopabvcqpcrqpgtqkuuxwcibfjuvbiiseiofjsokchojhizbvyibpdfxqdvijmewflbwykpubhmddkiyvpml
	condition:
		any of ($a_*)
 
}