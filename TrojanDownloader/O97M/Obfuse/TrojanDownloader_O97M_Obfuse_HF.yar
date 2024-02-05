
rule TrojanDownloader_O97M_Obfuse_HF{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.HF,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 73 67 42 6f 78 20 22 76 64 66 67 68 65 66 64 67 66 67 22 } //01 00 
		$a_01_1 = {4d 73 67 42 6f 78 20 22 64 66 67 33 64 73 66 64 73 66 22 } //01 00 
		$a_01_2 = {67 65 74 55 72 6c 33 20 3d 20 22 68 74 74 70 3a 2f 2f 35 31 2e 37 35 2e 31 33 33 2e 31 36 35 2f 22 } //00 00 
	condition:
		any of ($a_*)
 
}