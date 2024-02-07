
rule VirTool_BAT_Quiltran_H{
	meta:
		description = "VirTool:BAT/Quiltran.H,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 61 69 6e 2e 62 6f 6f } //01 00  Main.boo
		$a_01_1 = {53 74 61 67 65 2e 62 6f 6f } //01 00  Stage.boo
		$a_01_2 = {53 79 73 74 65 6d 2e 57 65 62 2e 45 78 74 65 6e 73 69 6f 6e 73 } //01 00  System.Web.Extensions
		$a_01_3 = {47 55 49 44 3a 20 7b 30 7d } //01 00  GUID: {0}
		$a_01_4 = {50 53 4b 3a 20 7b 30 7d } //01 00  PSK: {0}
		$a_01_5 = {55 52 4c 53 3a 20 7b 30 7d } //01 00  URLS: {0}
		$a_01_6 = {53 54 2e 65 78 65 20 3c } //01 00  ST.exe <
		$a_01_7 = {5b 2d 5d 20 41 74 74 65 6d 70 74 20 23 7b 30 7d } //01 00  [-] Attempt #{0}
		$a_01_8 = {5b 2a 5d 20 41 74 74 65 6d 70 74 69 6e 67 20 48 54 54 50 20 50 4f 53 54 20 74 6f 20 7b 30 7d } //00 00  [*] Attempting HTTP POST to {0}
		$a_00_9 = {96 55 00 00 00 00 } //51 00 
	condition:
		any of ($a_*)
 
}