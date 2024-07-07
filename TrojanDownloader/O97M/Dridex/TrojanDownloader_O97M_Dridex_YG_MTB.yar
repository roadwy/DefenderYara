
rule TrojanDownloader_O97M_Dridex_YG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.YG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 6f 6d 20 49 6e 20 45 3a 20 66 6b 20 3d 20 4c 65 6e 28 45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 28 72 6f 6d 29 29 3a 20 4e 65 78 74 3a 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 57 69 6e 64 6f 77 53 74 61 74 65 } //1 rom In E: fk = Len(ExecuteExcel4Macro(rom)): Next: Application.WindowState
		$a_01_1 = {69 6d 61 67 67 69 20 3d 20 69 6d 61 67 67 69 20 26 20 43 68 72 28 54 29 3a 20 54 20 3d 20 22 22 3a 20 4e 65 78 74 3a 20 45 20 3d 20 53 70 6c 69 74 28 69 6d 61 67 67 69 2c 20 6f 29 } //1 imaggi = imaggi & Chr(T): T = "": Next: E = Split(imaggi, o)
		$a_01_2 = {63 69 73 20 3d 20 43 65 6c 6c 73 28 61 2c 20 4b 29 3a 20 49 66 20 49 73 45 6d 70 74 79 28 63 69 73 29 } //1 cis = Cells(a, K): If IsEmpty(cis)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}