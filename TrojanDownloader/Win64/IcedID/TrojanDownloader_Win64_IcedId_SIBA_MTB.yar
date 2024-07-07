
rule TrojanDownloader_Win64_IcedId_SIBA_MTB{
	meta:
		description = "TrojanDownloader:Win64/IcedId.SIBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {4c 8b c1 84 c0 75 90 01 01 4c 8b c9 41 ba 90 01 04 41 bb 90 01 04 41 0f b6 11 b8 90 01 04 2b c2 8d 0c 80 41 8b c3 c1 e1 90 01 01 f7 e9 03 d1 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 6b c2 90 01 01 2b c8 41 8b c3 83 c1 90 01 01 f7 e9 03 d1 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 6b c2 90 01 01 2b c8 41 88 09 49 ff c1 49 83 ea 90 01 01 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}