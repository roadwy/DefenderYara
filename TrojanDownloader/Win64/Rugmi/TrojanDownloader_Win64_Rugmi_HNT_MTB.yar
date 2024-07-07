
rule TrojanDownloader_Win64_Rugmi_HNT_MTB{
	meta:
		description = "TrojanDownloader:Win64/Rugmi.HNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 69 c0 3f 00 01 00 48 83 c2 02 0f b7 c8 44 03 c1 49 83 e9 01 75 d9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}