
rule TrojanDownloader_Win64_Rugmi_HNP_MTB{
	meta:
		description = "TrojanDownloader:Win64/Rugmi.HNP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 b8 00 10 00 00 [0-30] 04 01 [0-b0] c7 44 24 ?? 00 00 00 00 c7 44 24 ?? 80 00 00 00 [0-08] c7 44 24 ?? 03 00 00 00 ff [0-f0] 0f 6f 40 [0-03] 83 [0-08] 0f 11 40 [0-f0] 63 ?? 3c [0-04] 89 [0-05] 8b ?? ?? 2c [0-2b] ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}