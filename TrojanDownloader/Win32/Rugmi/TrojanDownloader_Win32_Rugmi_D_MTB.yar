
rule TrojanDownloader_Win32_Rugmi_D_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 8b 40 20 8b 4d e4 0f be 04 08 85 c0 74 21 8b 45 fc 8b 40 20 8b 4d e4 66 0f be 04 08 8b 4d e4 8b 55 c4 66 89 04 4a 8b 45 e4 40 89 45 e4 eb ce } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}
rule TrojanDownloader_Win32_Rugmi_D_MTB_2{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 41 3c 89 85 30 fe ff ff 8b 45 dc 8b 8d 30 fe ff ff 8b 95 2c fe ff ff 03 44 d1 78 89 45 84 8b 45 dc 8b 4d 84 03 41 20 89 85 34 fe ff ff 8b 45 dc 8b 4d 84 03 41 1c } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}