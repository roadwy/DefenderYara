
rule TrojanDownloader_O97M_Malgent_AJK_MSR{
	meta:
		description = "TrojanDownloader:O97M/Malgent.AJK!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,0f 00 0f 00 03 00 00 05 00 "
		
	strings :
		$a_00_0 = {43 61 6c 6c 20 74 72 65 6e 65 73 28 22 68 74 74 70 3a 2f 2f 6b 75 7a 6f 76 2d 72 65 6d 6f 6e 74 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 6a 73 2f 77 69 6e 2e 65 78 65 22 2c } //05 00  Call trenes("http://kuzov-remont.com/wp-admin/js/win.exe",
		$a_00_1 = {45 6e 76 69 72 6f 6e 28 22 41 70 70 44 61 74 61 22 29 20 26 20 22 5c 44 73 2e 65 78 65 22 29 } //05 00  Environ("AppData") & "\Ds.exe")
		$a_00_2 = {45 6e 76 69 72 6f 6e 28 22 55 73 65 72 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 4d 65 6e fa 20 49 6e 69 63 69 6f 5c 50 72 6f 67 72 61 6d 61 73 5c 49 6e 69 63 69 6f 5c 44 73 2e 65 78 65 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}