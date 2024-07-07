
rule TrojanDownloader_Win64_Stealer_WE_MTB{
	meta:
		description = "TrojanDownloader:Win64/Stealer.WE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {42 0f b6 84 90 01 05 49 ff c0 ff c1 41 30 40 90 01 01 48 ff c2 49 ff c9 75 90 00 } //2
		$a_81_1 = {70 61 79 6c 6f 61 64 2e 62 69 6e } //1 payload.bin
		$a_81_2 = {6c 6f 61 64 65 72 2e 62 69 6e } //1 loader.bin
	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}