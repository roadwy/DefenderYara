
rule TrojanDownloader_O97M_EncDoc_ERT_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.ERT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 74 72 65 73 28 29 } //1 Public Function tres()
		$a_01_1 = {47 65 72 74 20 3d 20 22 46 69 6c 65 73 22 } //1 Gert = "Files"
		$a_01_2 = {42 79 79 74 75 69 74 79 20 3d 20 22 42 35 36 22 } //1 Byytuity = "B56"
		$a_01_3 = {42 79 79 74 75 69 74 79 31 20 3d 20 22 42 36 30 22 } //1 Byytuity1 = "B60"
		$a_01_4 = {47 75 69 6b 67 68 6a 67 66 68 20 3d 20 48 4a 48 47 75 79 20 26 20 48 4a 48 47 75 79 31 20 26 20 48 4a 48 47 75 79 32 20 26 20 48 4a 48 47 75 79 33 20 26 20 53 68 65 65 74 73 28 47 65 72 74 29 2e 52 61 6e 67 65 28 42 79 79 74 75 69 74 79 31 29 } //1 Guikghjgfh = HJHGuy & HJHGuy1 & HJHGuy2 & HJHGuy3 & Sheets(Gert).Range(Byytuity1)
		$a_01_5 = {42 74 64 75 66 6a 6b 68 6e 20 3d 20 53 68 65 65 74 73 28 47 65 72 74 29 2e 52 61 6e 67 65 28 42 79 79 74 75 69 74 79 29 } //1 Btdufjkhn = Sheets(Gert).Range(Byytuity)
		$a_03_6 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 47 75 69 6b 67 68 6a 67 66 68 2c 20 42 74 64 75 66 6a 6b 68 6e 2c 20 30 2c 20 30 90 0c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=7
 
}