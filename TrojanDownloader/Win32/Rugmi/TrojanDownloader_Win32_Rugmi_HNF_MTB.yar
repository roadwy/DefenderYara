
rule TrojanDownloader_Win32_Rugmi_HNF_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.HNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 ca 89 10 83 45 ?? 01 90 09 30 00 [0-30] 8b 45 ?? 39 45 ?? 76 [0-08] 8b 45 [0-08] 8b 08 [0-10] 01 ca [0-10] 83 45 ?? 01 [0-10] 83 c0 04 [0-08] 89 45 [0-08] eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}