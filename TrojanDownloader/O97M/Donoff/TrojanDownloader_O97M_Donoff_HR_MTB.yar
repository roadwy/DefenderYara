
rule TrojanDownloader_O97M_Donoff_HR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.HR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 36 32 2e 32 34 38 2e 32 32 35 2e 39 37 2f 31 2e 70 68 70 90 0a 1b 00 68 74 74 70 3a 2f 2f 90 00 } //01 00 
		$a_01_1 = {66 68 67 61 6a 6b 6c 61 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}