
rule TrojanDownloader_O97M_Powdow_VAM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.VAM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 61 6c 61 6c 61 61 6c 7a 64 61 66 61 6c 7a } //01 00 
		$a_01_1 = {7a 66 61 66 6c 7a 61 6c 66 61 6c } //01 00 
		$a_01_2 = {7a 64 61 6c 66 6c 61 66 6c } //00 00 
	condition:
		any of ($a_*)
 
}