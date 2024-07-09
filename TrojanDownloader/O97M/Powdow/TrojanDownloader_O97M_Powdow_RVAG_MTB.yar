
rule TrojanDownloader_O97M_Powdow_RVAG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVAG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 = CreateObject("WScript.Shell")
		$a_03_1 = {2e 4f 70 65 6e 20 22 67 65 74 22 2c 20 [0-64] 28 22 68 ?? ?? ?? ?? 3a 2f 2f 77 77 77 2e [0-64] 22 29 2c 20 46 61 6c 73 65 } //1
		$a_01_2 = {41 70 70 44 61 74 61 20 26 20 43 68 72 28 41 73 63 28 78 49 6d 69 66 69 6a 66 78 29 20 2d 20 31 29 } //1 AppData & Chr(Asc(xImifijfx) - 1)
		$a_01_3 = {4d 69 64 28 65 6e 63 2c 20 69 4f 49 4a 4f 6a 68 69 68 67 75 67 6b 68 69 2c 20 31 29 } //1 Mid(enc, iOIJOjhihgugkhi, 1)
		$a_01_4 = {3d 20 57 73 68 53 68 65 6c 6c 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 52 65 63 65 6e 74 22 29 } //1 = WshShell.SpecialFolders("Recent")
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}