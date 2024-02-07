
rule TrojanDownloader_O97M_Thawoxy_A{
	meta:
		description = "TrojanDownloader:O97M/Thawoxy.A,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00  = CreateObject("WScript.Shell")
		$a_01_1 = {2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 22 25 41 4c 4c 55 53 45 52 53 50 52 4f 46 49 4c 45 25 22 29 } //01 00  .ExpandEnvironmentStrings("%ALLUSERSPROFILE%")
		$a_01_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //01 00  = CreateObject("Scripting.FileSystemObject")
		$a_01_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 41 64 6f 64 62 2e 53 74 72 65 61 6d 22 29 } //01 00  = CreateObject("Adodb.Stream")
		$a_01_4 = {2e 46 6f 6c 64 65 72 45 78 69 73 74 73 28 68 78 61 33 68 32 79 29 29 20 54 68 65 6e } //00 00  .FolderExists(hxa3h2y)) Then
	condition:
		any of ($a_*)
 
}