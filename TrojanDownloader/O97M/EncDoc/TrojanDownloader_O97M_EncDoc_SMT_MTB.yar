
rule TrojanDownloader_O97M_EncDoc_SMT_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SMT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 31 38 2e 31 35 39 2e 35 39 2e 32 35 33 2f 63 75 74 2f 33 39 36 31 38 30 39 39 39 37 34 36 30 36 37 2e 62 61 74 22 22 20 4d 67 65 6d 62 67 67 78 6d 78 61 6c 64 75 7a 2e 65 78 65 2e 65 78 65 20 26 26 20 4d 67 65 6d 62 67 67 78 6d 78 61 6c 64 75 7a 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29 } //00 00  -split -f ""http://18.159.59.253/cut/396180999746067.bat"" Mgembggxmxalduz.exe.exe && Mgembggxmxalduz.exe.exe", vbHide)
	condition:
		any of ($a_*)
 
}