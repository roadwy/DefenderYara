
rule TrojanDownloader_Win64_Latot_ARAC_MTB{
	meta:
		description = "TrojanDownloader:Win64/Latot.ARAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 ff c1 41 f7 e8 8b c2 c1 e8 1f 03 d0 0f b6 c2 02 c0 02 d0 41 0f b6 c0 41 ff c0 2a c2 04 02 00 44 31 ff 49 3b c9 7c d3 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}