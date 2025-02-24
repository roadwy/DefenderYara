
rule TrojanDownloader_Win32_Rugmi_DF_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 f4 8b 45 f4 8b 48 0c 89 4d f0 8b 55 f0 83 c2 0c 89 55 fc 8b 45 fc 89 45 e8 b9 01 00 00 00 85 c9 74 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}