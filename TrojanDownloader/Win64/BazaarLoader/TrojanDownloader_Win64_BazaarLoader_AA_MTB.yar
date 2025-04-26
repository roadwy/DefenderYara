
rule TrojanDownloader_Win64_BazaarLoader_AA_MTB{
	meta:
		description = "TrojanDownloader:Win64/BazaarLoader.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c1 6b c8 3e b8 09 04 02 81 f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 2b c8 b8 09 04 02 81 83 c1 7f f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 2b c8 42 ?? ?? ?? ?? 49 ff c0 49 83 f8 ?? 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}