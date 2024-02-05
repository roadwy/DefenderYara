
rule TrojanDownloader_O97M_Obfuse_SLL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SLL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } //01 00 
		$a_01_1 = {32 45 34 34 36 46 37 37 36 45 36 43 36 46 36 31 36 34 34 36 36 39 36 43 36 35 32 38 32 37 36 38 37 34 37 34 37 30 37 33 33 41 32 46 32 46 37 37 37 37 37 37 32 45 37 36 36 46 36 39 36 35 37 36 36 46 36 34 37 35 36 43 36 37 36 35 36 43 37 35 32 45 37 32 36 46 32 46 36 46 37 37 36 45 36 33 36 43 36 46 37 35 36 34 32 46 36 39 36 45 36 34 36 35 37 38 32 45 37 30 36 38 37 30 32 46 37 33 32 46 37 33 35 38 33 38 37 33 36 31 37 32 36 45 33 37 34 37 33 30 34 33 36 44 37 35 37 33 37 41 32 46 36 34 36 46 37 37 36 45 36 43 36 46 36 31 36 34 32 37 32 43 } //00 00 
	condition:
		any of ($a_*)
 
}