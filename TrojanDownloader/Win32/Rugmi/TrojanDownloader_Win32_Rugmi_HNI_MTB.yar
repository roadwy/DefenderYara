
rule TrojanDownloader_Win32_Rugmi_HNI_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.HNI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 45 10 89 45 fc b8 ff ff ff 90 01 01 03 45 10 89 45 10 8b 45 fc 85 c0 74 23 8b 45 0c 8b 55 08 0f be 00 88 02 b8 01 00 00 00 03 45 08 89 45 08 b8 01 00 00 00 03 45 0c 89 45 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}