
rule TrojanDownloader_BAT_PassStlr_SA{
	meta:
		description = "TrojanDownloader:BAT/PassStlr.SA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 55 73 65 53 79 73 74 65 6d 50 61 73 73 77 6f 72 64 43 68 61 72 } //01 00  get_UseSystemPasswordChar
		$a_01_1 = {5c 59 6f 75 20 43 6c 65 61 6e 20 50 43 5c 6f 62 6a 5c 44 65 62 75 67 5c 59 6f 75 20 43 6c 65 61 6e 20 50 43 2e 70 64 62 } //01 00  \You Clean PC\obj\Debug\You Clean PC.pdb
		$a_01_2 = {24 32 61 61 62 32 37 66 63 2d 34 34 63 33 2d 34 35 64 39 2d 61 62 31 30 2d 61 35 35 31 36 36 63 66 32 30 32 62 } //00 00  $2aab27fc-44c3-45d9-ab10-a55166cf202b
	condition:
		any of ($a_*)
 
}