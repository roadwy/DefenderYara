
rule TrojanDownloader_Win64_Rugmi_AS_MTB{
	meta:
		description = "TrojanDownloader:Win64/Rugmi.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 44 24 ?? 48 8b 8c 24 ?? ?? ?? ?? 48 03 c8 48 8b c1 48 89 84 24 ?? ?? ?? ?? 48 8b 84 24 ?? ?? ?? ?? 8b 8c 24 ?? ?? ?? ?? 8b 00 33 c1 48 8b 8c 24 ?? ?? ?? ?? 89 01 8b 44 24 ?? 83 c0 ?? 89 44 24 ?? eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}