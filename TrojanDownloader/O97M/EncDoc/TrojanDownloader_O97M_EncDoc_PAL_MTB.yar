
rule TrojanDownloader_O97M_EncDoc_PAL_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 72 6c 3d 22 68 74 74 70 3a 2f 2f 31 37 32 2e 31 36 2e 37 39 2e 31 39 32 2f 68 61 6e 64 73 6f 6e 2e 62 61 74 22 63 6f 6e 73 74 } //01 00  url="http://172.16.79.192/handson.bat"const
		$a_01_1 = {2c 32 27 31 3d 6e 6f 6f 76 65 72 77 72 69 74 65 2c 32 3d 6f 76 65 72 77 72 69 74 65 6f 73 74 72 65 61 6d 2e 63 6c 6f 73 65 27 65 78 65 63 75 74 65 28 68 69 64 65 77 69 6e 64 6f 77 29 73 68 65 6c 6c 66 69 6c 65 70 61 74 68 2c 76 62 68 69 64 65 65 6e 64 69 66 65 6e 64 } //00 00  ,2'1=nooverwrite,2=overwriteostream.close'execute(hidewindow)shellfilepath,vbhideendifend
	condition:
		any of ($a_*)
 
}