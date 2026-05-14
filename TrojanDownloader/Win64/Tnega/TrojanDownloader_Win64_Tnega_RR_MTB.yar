
rule TrojanDownloader_Win64_Tnega_RR_MTB{
	meta:
		description = "TrojanDownloader:Win64/Tnega.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 eb 03 d3 c1 fa 05 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 33 0f b6 c3 2a c1 04 36 41 30 00 ff c3 4d 8d 40 01 83 fb 19 7c d2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}