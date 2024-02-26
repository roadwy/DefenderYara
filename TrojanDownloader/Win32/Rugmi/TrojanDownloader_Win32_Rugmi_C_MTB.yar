
rule TrojanDownloader_Win32_Rugmi_C_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 45 c0 03 45 90 01 01 89 45 a4 8b 45 a4 8b 90 01 01 33 85 58 90 01 03 8b 4d a4 89 01 8b 45 d4 83 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}