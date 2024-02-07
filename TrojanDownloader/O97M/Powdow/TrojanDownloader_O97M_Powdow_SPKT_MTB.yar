
rule TrojanDownloader_O97M_Powdow_SPKT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SPKT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 65 77 2d 4f 62 6a 22 20 2b 20 69 4a 72 65 74 79 2e 6f 64 6a 72 20 2b 20 22 20 22 20 2b 20 69 4a 72 65 74 79 2e 4a 48 64 68 72 20 2b 20 22 65 74 2e 57 65 22 20 2b 20 69 4a 72 65 74 79 2e 6b 64 6a 72 20 2b 20 22 74 29 } //01 00  New-Obj" + iJrety.odjr + " " + iJrety.JHdhr + "et.We" + iJrety.kdjr + "t)
		$a_01_1 = {68 22 20 2b 20 7a 78 73 66 71 77 72 69 72 2e 69 73 67 65 6a 66 20 2b 20 22 67 68 74 6c 22 20 2b 20 7a 78 73 66 71 77 72 69 72 2e 62 64 6f 69 72 67 20 2b 20 22 69 74 65 6e 64 6f 6d } //01 00  h" + zxsfqwrir.isgejf + "ghtl" + zxsfqwrir.bdoirg + "itendom
		$a_01_2 = {3d 20 22 74 61 72 74 2d } //01 00  = "tart-
		$a_01_3 = {25 54 4d 50 25 5c 61 6c 6c 61 79 61 2e 65 78 65 27 29 3b 53 22 20 2b 20 4c 44 72 57 4b 65 20 2b 20 22 50 72 6f 22 20 2b 20 22 63 65 73 73 20 27 25 54 4d 50 25 5c 61 6c 6c 61 79 61 2e 65 78 65 } //00 00  %TMP%\allaya.exe');S" + LDrWKe + "Pro" + "cess '%TMP%\allaya.exe
	condition:
		any of ($a_*)
 
}