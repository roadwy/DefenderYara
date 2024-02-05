
rule TrojanDownloader_BAT_Malloc_GC_MTB{
	meta:
		description = "TrojanDownloader:BAT/Malloc.GC!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 00 78 00 65 00 69 00 7a 00 63 00 63 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 38 00 30 00 2e 00 36 00 36 00 2e 00 37 00 35 00 2e 00 33 00 37 00 2f 00 47 00 66 00 6a 00 74 00 77 00 62 00 6e 00 65 00 2e 00 70 00 6e 00 67 00 } //01 00 
		$a_01_2 = {4b 00 6a 00 61 00 6a 00 67 00 6a 00 76 00 62 00 69 00 6c 00 6e 00 2e 00 42 00 68 00 6a 00 65 00 73 00 6e 00 63 00 6e 00 79 00 73 00 73 00 79 00 } //00 00 
	condition:
		any of ($a_*)
 
}