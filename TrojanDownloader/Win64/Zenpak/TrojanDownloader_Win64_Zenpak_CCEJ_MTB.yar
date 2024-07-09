
rule TrojanDownloader_Win64_Zenpak_CCEJ_MTB{
	meta:
		description = "TrojanDownloader:Win64/Zenpak.CCEJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 54 24 ?? 48 89 7c 24 40 48 8d b8 ?? ?? ?? ?? 4c 8d 4c 24 ?? 48 8b cf 41 b8 40 00 00 00 ff 15 } //1
		$a_01_1 = {70 00 61 00 79 00 6c 00 6f 00 61 00 64 00 2e 00 62 00 69 00 6e 00 } //1 payload.bin
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}