
rule TrojanDownloader_Win64_Penguish_PO_MTB{
	meta:
		description = "TrojanDownloader:Win64/Penguish.PO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff c0 89 44 24 ?? 83 7c 24 ?? ?? 7f ?? 8b 44 24 ?? 8b 4c 24 ?? 33 c8 8b c1 85 c0 7d ?? 8b 44 24 ?? d1 e0 33 44 24 ?? 89 44 24 ?? eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}