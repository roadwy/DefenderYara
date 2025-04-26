
rule TrojanDownloader_Win32_Rugmi_HNAE_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.HNAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f be 00 85 c0 74 24 8b 45 ?? 03 45 ?? 66 0f be 00 8b 4d ?? 8b 55 ?? 66 89 04 4a 8b 45 90 1b 02 40 89 45 90 1b 02 8b 45 90 1b 01 40 89 45 90 1b 01 eb } //10
		$a_03_1 = {ff 55 98 89 45 ?? 8b 45 ?? ?? ?? ?? 8b 45 fc ff 70 ?? 8b ?? fc ff 70 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}