
rule TrojanDownloader_O97M_Obfuse_KAG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.KAG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 61 6f 73 6b 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 } //01 00  kaosk = GetObject(
		$a_01_1 = {6b 61 6f 73 6b 2e 63 6f 70 79 66 69 6c 65 } //01 00  kaosk.copyfile
		$a_01_2 = {6b 6f 6b 6f 6b 61 73 64 20 3d 20 52 65 70 6c 61 63 65 28 } //01 00  kokokasd = Replace(
		$a_01_3 = {61 64 6a 61 69 77 64 6a 69 61 73 6b 64 20 3d 20 52 65 70 6c 61 63 65 28 } //01 00  adjaiwdjiaskd = Replace(
		$a_01_4 = {47 65 74 4f 62 6a 65 63 74 28 61 64 6a 61 69 77 64 6a 69 61 73 6b 64 29 2e 20 5f } //01 00  GetObject(adjaiwdjiaskd). _
		$a_01_5 = {47 65 74 28 61 6b 73 64 6f 6b 61 73 6f 64 6b 6f 61 6b 73 64 29 2e 20 5f } //00 00  Get(aksdokasodkoaksd). _
	condition:
		any of ($a_*)
 
}