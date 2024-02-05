
rule TrojanDownloader_WinNT_AlienSpy_A{
	meta:
		description = "TrojanDownloader:WinNT/AlienSpy.A,SIGNATURE_TYPE_JAVAHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {35 53 65 74 20 6f 53 68 65 6c 6c 20 3d 20 57 53 63 72 69 70 74 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 20 28 22 57 53 43 72 69 70 74 2e 73 68 65 6c 6c 22 29 90 02 ff 6f 53 68 65 6c 6c 2e 72 75 6e 20 22 90 02 ff 22 22 20 2d 6a 61 72 20 22 22 90 02 ff 73 46 75 6e 63 74 69 6f 6e 20 3d 20 22 57 53 63 72 69 70 74 2e 53 6c 65 65 70 20 33 30 30 30 3a 20 53 65 74 20 4d 65 6c 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}