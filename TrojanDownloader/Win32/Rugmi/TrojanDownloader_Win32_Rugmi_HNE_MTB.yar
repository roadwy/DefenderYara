
rule TrojanDownloader_Win32_Rugmi_HNE_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.HNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {85 c0 0f 95 c0 84 c0 74 90 01 01 8b 45 0c 0f b6 00 8b 55 90 09 30 00 90 02 25 55 89 e5 83 ec 90 02 20 8d 50 ff 90 02 20 88 02 90 02 20 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}