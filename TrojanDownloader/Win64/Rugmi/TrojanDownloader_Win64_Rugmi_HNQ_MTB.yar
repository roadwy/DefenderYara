
rule TrojanDownloader_Win64_Rugmi_HNQ_MTB{
	meta:
		description = "TrojanDownloader:Win64/Rugmi.HNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 b8 00 10 00 00 [0-15] ff 15 [0-40] b8 04 01 00 00 [0-f4] c7 44 24 30 00 00 00 00 c7 44 24 28 80 00 00 00 [0-30] ff 15 } //5
		$a_03_1 = {48 63 40 3c 48 8b 8c 24 ?? 00 00 00 48 03 c8 48 8b c1 48 89 84 24 ?? 00 00 00 48 8b 84 24 ?? 00 00 00 8b 40 2c } //1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*1) >=6
 
}