
rule TrojanDownloader_Win32_Rugmi_HNA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.HNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {85 c0 0f 95 c0 84 c0 74 15 8b 45 90 01 01 0f b6 00 8b 55 90 01 01 88 02 83 45 90 01 01 01 83 45 90 01 01 01 eb d9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}