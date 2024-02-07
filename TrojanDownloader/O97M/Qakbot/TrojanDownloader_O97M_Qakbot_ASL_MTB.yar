
rule TrojanDownloader_O97M_Qakbot_ASL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.ASL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 67 48 6e 62 66 4b 74 5c } //01 00  C:\gHnbfKt\
		$a_01_1 = {68 74 66 42 6a 2e 64 6c 6c } //01 00  htfBj.dll
		$a_03_2 = {68 74 74 70 3a 2f 2f 90 02 04 6e 61 72 75 6d 69 2e 6d 6e 2f 64 73 2f 30 34 31 32 32 30 2e 67 69 66 90 00 } //01 00 
		$a_03_3 = {68 74 74 70 3a 2f 2f 90 02 04 74 65 74 65 6b 2e 72 75 2f 64 73 2f 30 34 31 32 32 30 2e 67 69 66 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}