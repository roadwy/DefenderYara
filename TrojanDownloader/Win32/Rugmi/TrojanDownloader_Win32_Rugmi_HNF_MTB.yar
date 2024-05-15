
rule TrojanDownloader_Win32_Rugmi_HNF_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.HNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 ca 89 10 83 45 90 01 01 01 90 09 30 00 90 02 30 8b 45 90 01 01 39 45 90 01 01 76 90 02 08 8b 45 90 02 08 8b 08 90 02 10 01 ca 90 02 10 83 45 90 01 01 01 90 02 10 83 c0 04 90 02 08 89 45 90 02 08 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}