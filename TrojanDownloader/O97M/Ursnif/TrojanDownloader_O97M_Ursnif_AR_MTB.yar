
rule TrojanDownloader_O97M_Ursnif_AR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0c 00 0c 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 20 28 } //0a 00  URLDownloadToFileA" (
		$a_01_1 = {62 61 63 2e 39 6b 6f 6e 3d 6c 3f 70 68 70 2e 70 32 33 69 30 6f 69 61 2f 35 38 6f 6c 30 32 65 77 2f 6d 6f 63 2e 38 66 6a 6a 66 62 62 2f 2f 3a 70 74 74 68 22 2c } //01 00  bac.9kon=l?php.p23i0oia/58ol02ew/moc.8fjjfbb//:ptth",
		$a_03_2 = {28 22 74 6d 70 22 29 20 26 20 22 5c 90 02 09 2e 74 6d 70 22 90 00 } //00 00 
		$a_00_3 = {8f 83 00 00 05 00 05 00 05 00 00 } //01 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Ursnif_AR_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 43 68 72 28 31 31 35 20 2b 20 30 29 20 2b 20 22 48 45 4c 4c 2e 22 } //01 00  = Chr(115 + 0) + "HELL."
		$a_03_1 = {2e 43 6f 6e 74 72 6f 6c 73 28 90 02 55 29 2e 54 65 78 74 90 00 } //01 00 
		$a_03_2 = {4f 70 65 6e 20 54 72 69 6d 28 90 02 55 29 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 90 00 } //01 00 
		$a_03_3 = {50 72 69 6e 74 20 23 90 01 01 2c 20 54 72 69 6d 28 90 00 } //01 00 
		$a_01_4 = {2e 56 61 6c 75 65 } //00 00  .Value
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Ursnif_AR_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 45 6e 76 69 72 6f 6e 28 90 02 0f 29 0d 0a 49 66 20 53 65 63 6f 6e 64 28 22 90 02 02 3a 90 02 02 3a 90 02 02 22 29 20 3d 20 22 90 04 02 03 30 2d 39 22 20 54 68 65 6e 0d 0a 90 02 0a 20 3d 20 52 65 70 6c 61 63 65 28 90 1b 05 2c 20 22 5c 22 2c 20 22 5c 5c 22 29 90 00 } //01 00 
		$a_03_1 = {52 65 70 6c 61 63 65 28 90 02 0f 2c 20 22 5c 22 2c 20 22 5c 5c 22 29 90 0a 28 00 90 1b 00 20 3d 20 90 00 } //01 00 
		$a_01_2 = {4d 73 67 42 6f 78 20 28 22 45 72 72 6f 72 3a 22 20 26 20 76 62 43 72 4c 66 20 26 20 22 43 6f 6e 74 65 6e 74 20 6e 6f 74 20 61 76 61 69 6c 61 62 6c 65 22 29 } //01 00  MsgBox ("Error:" & vbCrLf & "Content not available")
		$a_03_3 = {53 65 74 20 90 02 0f 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 90 02 5f 44 69 6d 20 90 02 0f 20 41 73 20 4f 62 6a 65 63 74 90 08 00 04 53 65 74 20 90 1b 02 20 3d 20 90 1b 00 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 90 02 0f 2c 20 54 72 75 65 2c 20 54 72 75 65 29 90 02 0a 90 1b 02 2e 57 72 69 74 65 90 00 } //00 00 
		$a_00_4 = {cf 18 00 00 } //09 33 
	condition:
		any of ($a_*)
 
}