
rule TrojanDownloader_O97M_Powdow_MN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.MN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 74 61 72 74 2d 70 72 6f 63 65 73 73 28 24 65 6e 76 3a 41 50 50 44 41 54 41 2b 27 5c 5c 27 2b 27 72 65 63 6f 6d 2e 76 62 73 } //01 00  start-process($env:APPDATA+'\\'+'recom.vbs
		$a_00_1 = {68 74 74 70 73 3a 2f 2f 63 2e 74 6f 70 34 74 6f 70 2e 69 6f 2f 70 5f 31 38 33 32 64 71 6b 31 30 31 2e 6a 70 67 } //01 00  https://c.top4top.io/p_1832dqk101.jpg
		$a_00_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e } //01 00  CreateObject("WScript.Shell").Run
		$a_00_3 = {22 77 65 72 73 68 65 6c 6c 22 } //00 00  "wershell"
	condition:
		any of ($a_*)
 
}