
rule TrojanDownloader_Win64_Fragtor_ARA_MTB{
	meta:
		description = "TrojanDownloader:Win64/Fragtor.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 0c 30 ff c0 88 0c 3b ff c3 3b 44 24 40 72 ef } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}