
rule TrojanDownloader_O97M_Donoff_CA{
	meta:
		description = "TrojanDownloader:O97M/Donoff.CA,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {3c 3e 20 32 30 30 20 54 68 65 6e } //1 <> 200 Then
		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 4c 74 6e 45 77 76 58 68 78 73 4f 44 28 22 6e 6e 67 6a 55 30 76 72 6b 74 65 55 59 22 29 29 } //2 = CreateObject(LtnEwvXhxsOD("nngjU0vrkteUY"))
		$a_01_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 28 4c 74 6e 45 77 76 58 68 78 73 4f 44 28 22 47 79 53 43 43 45 69 7a 7c 51 4d 75 22 29 29 } //3 Application.Run (LtnEwvXhxsOD("GySCCEiz|QMu"))
		$a_01_3 = {28 22 31 22 29 20 26 20 52 6e 64 } //2 ("1") & Rnd
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 41 6e 64 53 61 76 65 20 3d 20 46 61 6c 73 65 } //1 DownloadAndSave = False
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=9
 
}