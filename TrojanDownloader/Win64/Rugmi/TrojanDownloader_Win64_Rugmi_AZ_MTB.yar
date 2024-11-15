
rule TrojanDownloader_Win64_Rugmi_AZ_MTB{
	meta:
		description = "TrojanDownloader:Win64/Rugmi.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {f3 0f 6f 00 83 c2 10 66 0f fe c1 f3 0f 7f 00 f3 0f 6f 40 10 66 0f fe c1 f3 0f 7f 40 10 f3 0f 6f 40 20 66 0f fe c1 f3 0f 7f 40 20 f3 0f 6f 40 30 66 0f fe c1 f3 0f 7f 40 30 48 83 c0 40 41 3b d1 72 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}