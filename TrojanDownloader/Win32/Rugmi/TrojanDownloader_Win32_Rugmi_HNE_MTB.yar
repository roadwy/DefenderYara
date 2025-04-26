
rule TrojanDownloader_Win32_Rugmi_HNE_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.HNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {85 c0 0f 95 c0 84 c0 74 ?? 8b 45 0c 0f b6 00 8b 55 90 09 30 00 [0-25] 55 89 e5 83 ec [0-20] 8d 50 ff [0-20] 88 02 [0-20] c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}