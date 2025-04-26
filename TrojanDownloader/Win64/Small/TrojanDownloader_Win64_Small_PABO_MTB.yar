
rule TrojanDownloader_Win64_Small_PABO_MTB{
	meta:
		description = "TrojanDownloader:Win64/Small.PABO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 4f ec c4 4e f7 ee c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 34 40 0f b6 c6 2a c1 04 39 41 30 00 ff c6 4d 8d 40 01 83 fe 26 } //1
		$a_01_1 = {b8 4f ec c4 4e 41 f7 e8 c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 34 41 0f b6 c0 2a c1 04 39 41 30 01 41 ff c0 4d 8d 49 01 41 83 f8 14 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}