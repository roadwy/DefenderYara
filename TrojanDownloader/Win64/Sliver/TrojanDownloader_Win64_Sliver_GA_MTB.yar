
rule TrojanDownloader_Win64_Sliver_GA_MTB{
	meta:
		description = "TrojanDownloader:Win64/Sliver.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 0f 57 ff 4c 8b 35 ca 5d 54 00 65 4d 8b 36 4d 8b 36 48 8b 44 24 08 48 83 c4 38 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}