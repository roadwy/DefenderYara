
rule TrojanDownloader_BAT_AveMariaRAT_Z_MTB{
	meta:
		description = "TrojanDownloader:BAT/AveMariaRAT.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 09 09 94 11 09 11 05 94 58 20 00 01 00 00 5d 94 13 06 11 0a 11 04 07 11 04 91 11 06 61 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 6c 65 67 61 74 65 } //01 00  CreateDelegate
		$a_01_2 = {47 65 74 54 79 70 65 } //00 00  GetType
	condition:
		any of ($a_*)
 
}