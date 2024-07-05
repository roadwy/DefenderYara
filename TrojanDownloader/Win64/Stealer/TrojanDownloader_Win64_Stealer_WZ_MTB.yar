
rule TrojanDownloader_Win64_Stealer_WZ_MTB{
	meta:
		description = "TrojanDownloader:Win64/Stealer.WZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {0f be 04 01 48 63 4c 24 10 48 8b 54 24 08 0f be 0c 0a 33 c1 48 63 4c 24 14 48 8b 54 24 30 88 04 0a 8b 44 24 10 83 c0 01 89 44 24 10 eb } //01 00 
		$a_81_1 = {70 61 79 6c 6f 61 64 2e 62 69 6e } //00 00  payload.bin
	condition:
		any of ($a_*)
 
}