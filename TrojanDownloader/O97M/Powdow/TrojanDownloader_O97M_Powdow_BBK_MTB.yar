
rule TrojanDownloader_O97M_Powdow_BBK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BBK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 55 70 46 52 4b 2c 20 22 53 68 22 20 2b 20 22 65 6c 22 20 2b 20 22 6c 45 78 65 22 20 2b 20 22 63 75 74 65 22 2c 20 56 62 4d 65 74 68 6f 64 2c 20 74 76 65 74 28 30 29 2c 20 74 76 65 74 28 31 29 2c 20 74 76 65 74 28 32 29 2c 20 74 76 65 74 28 33 29 2c 20 74 76 65 74 28 34 29 29 } //1 = CallByName(UpFRK, "Sh" + "el" + "lExe" + "cute", VbMethod, tvet(0), tvet(1), tvet(2), tvet(3), tvet(4))
		$a_01_1 = {59 49 49 50 63 61 77 6b 4d 20 3d 20 62 72 57 57 74 49 28 67 35 2c 20 67 36 29 } //1 YIIPcawkM = brWWtI(g5, g6)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}