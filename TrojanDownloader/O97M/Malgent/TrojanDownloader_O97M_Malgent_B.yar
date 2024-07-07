
rule TrojanDownloader_O97M_Malgent_B{
	meta:
		description = "TrojanDownloader:O97M/Malgent.B,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_00_0 = {3a 20 43 61 6c 6c 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 28 35 20 2d 20 35 2c 20 4e 38 6e 42 6e 2c 20 68 30 35 76 4e 75 34 4c 6d 43 79 59 2c 20 31 20 2d 20 31 2c 20 32 20 2d 20 32 29 } //1 : Call URLDownloadToFileA(5 - 5, N8nBn, h05vNu4LmCyY, 1 - 1, 2 - 2)
		$a_00_1 = {7a 6d 78 6e 20 3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 6a 74 72 61 2c 20 68 72 71 66 28 } //1 zmxn = CallByName(jtra, hrqf(
		$a_00_2 = {68 7a 6b 61 20 3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 6c 79 74 6c 2c 20 66 6c 67 63 28 } //1 hzka = CallByName(lytl, flgc(
		$a_00_3 = {65 70 20 3d 20 22 53 51 42 75 41 48 59 41 62 77 42 72 41 47 55 41 4c 51 42 46 41 48 67 41 63 41 42 79 41 47 55 41 63 77 42 7a 41 47 6b 41 62 77 42 75 41 43 41 41 4a 41 41 6f 41 45 34 41 5a 51 42 33 41 43 30 41 54 77 42 69 41 47 6f 41 5a 51 42 6a 41 48 51 41 49 41 42 4a 41 45 38 } //1 ep = "SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAJAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABJAE8
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=1
 
}