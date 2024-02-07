
rule TrojanDownloader_BAT_AgentTesla_BD_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {73 00 75 00 62 00 71 00 74 00 61 00 6e 00 65 00 6f 00 75 00 73 00 73 00 68 00 6f 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 4e 00 78 00 77 00 6c 00 79 00 6b 00 5f 00 54 00 6a 00 78 00 76 00 6f 00 6a 00 6d 00 77 00 2e 00 70 00 6e 00 67 00 } //05 00  subqtaneousshop.com/Nxwlyk_Tjxvojmw.png
		$a_01_1 = {57 15 a2 09 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 30 00 00 00 08 00 00 00 } //01 00 
		$a_01_2 = {47 6e 6f 67 6b 7a 7a 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Gnogkzz.Properties.Resources.resources
		$a_01_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_5 = {48 73 66 74 79 72 68 74 78 71 69 65 74 6f 6e 77 67 70 63 73 66 67 } //00 00  Hsftyrhtxqietonwgpcsfg
	condition:
		any of ($a_*)
 
}