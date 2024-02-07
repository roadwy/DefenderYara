
rule TrojanDownloader_O97M_Obfuse_PB_MSR{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PB!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {67 65 74 2d 69 63 6f 6e 73 2e 64 64 6e 73 2e 6e 65 74 2f 90 02 50 2f 2f 61 75 74 6f 69 6e 64 65 78 2e 70 68 70 90 00 } //01 00 
		$a_01_1 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 41 70 70 50 61 74 68 73 20 2b 20 22 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 74 65 6d 70 6c 61 74 65 73 2e 76 62 73 22 2c 20 54 72 75 65 2c 20 54 72 75 65 29 } //00 00  .CreateTextFile(AppPaths + "\Microsoft\Windows\Start Menu\Programs\Startup\templates.vbs", True, True)
	condition:
		any of ($a_*)
 
}