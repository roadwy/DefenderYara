
rule TrojanDownloader_O97M_Obfuse_PHJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PHJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 6f 75 72 63 65 20 68 74 74 60 70 3a 2f 2f 31 38 2e 31 39 35 2e 31 34 33 2e 31 38 33 2f 37 2f 37 2f 49 4d 47 5f 90 02 14 2e 65 60 78 65 90 00 } //01 00 
		$a_03_1 = {2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 90 02 14 2e 65 60 78 65 90 00 } //01 00 
		$a_01_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 73 68 65 65 65 20 26 20 22 6c 2e 61 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //01 00  = CreateObject(sheee & "l.application")
		$a_01_3 = {2e 4f 70 65 6e 28 62 65 68 61 76 69 6f 72 65 78 61 63 74 6c 79 29 } //00 00  .Open(behaviorexactly)
	condition:
		any of ($a_*)
 
}