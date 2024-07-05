
rule TrojanDownloader_Win64_Stealer_AB_MTB{
	meta:
		description = "TrojanDownloader:Win64/Stealer.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f be 04 01 48 63 4c 24 20 48 8b 54 24 50 0f be 0c 0a 33 c1 48 63 4c 24 24 48 8b 54 24 40 88 04 0a eb } //01 00 
		$a_81_1 = {70 61 79 6c 6f 61 64 2e 62 69 6e } //00 00  payload.bin
	condition:
		any of ($a_*)
 
}