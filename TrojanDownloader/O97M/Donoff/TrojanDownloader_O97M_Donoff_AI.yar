
rule TrojanDownloader_O97M_Donoff_AI{
	meta:
		description = "TrojanDownloader:O97M/Donoff.AI,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2b 20 22 2e 65 78 65 } //01 00  + ".exe
		$a_01_1 = {3d 20 22 53 63 72 69 70 74 69 6e 22 20 2b 20 22 67 2e 46 69 6c 65 53 22 20 2b } //01 00  = "Scriptin" + "g.FileS" +
		$a_01_2 = {3d 20 22 48 74 22 20 2b 20 22 74 22 20 2b 20 22 70 22 20 2b 20 22 2e } //01 00  = "Ht" + "t" + "p" + ".
		$a_01_3 = {2e 53 74 61 74 75 73 20 3d 20 35 30 20 2b 20 35 30 20 2b 20 31 30 30 20 54 68 65 6e } //00 00  .Status = 50 + 50 + 100 Then
	condition:
		any of ($a_*)
 
}