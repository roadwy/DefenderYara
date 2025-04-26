
rule TrojanDownloader_BAT_Crysan_RDA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Crysan.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {31 36 63 63 66 39 35 30 2d 64 31 30 66 2d 34 64 36 34 2d 39 31 65 30 2d 65 65 34 36 30 62 65 34 66 31 66 31 } //1 16ccf950-d10f-4d64-91e0-ee460be4f1f1
		$a_01_1 = {42 65 72 6e 79 53 70 6f 6f 66 65 72 } //1 BernySpoofer
		$a_01_2 = {53 74 6f 6e 65 6c 65 73 73 2d 32 34 35 37 } //1 Stoneless-2457
		$a_03_3 = {00 28 43 00 00 0a 03 ?? ?? ?? ?? ?? 16 1f 20 6f 40 00 00 0a 6f 44 00 00 0a 0a 28 43 00 00 0a 04 ?? ?? ?? ?? ?? 16 1f 10 6f 40 00 00 0a 6f 44 00 00 0a 0b 02 06 07 ?? ?? ?? ?? ?? 0c 2b 00 08 2a } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*2) >=5
 
}