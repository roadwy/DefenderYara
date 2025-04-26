
rule TrojanDownloader_Win32_Rugmi_DC_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f af c8 0f b6 14 73 03 ca 0f af c8 0f b6 54 73 ?? 46 03 ca 3b f7 72 } //1
		$a_03_1 = {0f af 44 24 ?? 0f b6 0c 2a 03 c1 45 3b ee 72 } //1
		$a_01_2 = {8b 44 24 04 8a 00 8b 0c 24 88 01 8b 04 24 83 c0 01 89 04 24 8b 44 24 04 83 c0 01 89 44 24 04 eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}