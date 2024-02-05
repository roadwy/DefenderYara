
rule TrojanDownloader_Win32_Banload_AD_MTB{
	meta:
		description = "TrojanDownloader:Win32/Banload.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 55 10 8a 02 a2 90 01 04 8b 4d 10 83 c1 01 89 4d 10 8b 55 0c 89 55 fc b8 90 01 04 03 45 08 8b 4d 0c 03 4d 08 8b 15 90 01 04 8b 35 90 01 04 8a 04 30 88 04 11 8b 4d 08 0f be 91 90 01 04 85 d2 75 90 00 } //01 00 
		$a_02_1 = {8b 45 0c 03 45 08 8b 0d 90 01 04 8a 14 08 32 15 90 01 04 8b 45 0c 03 45 08 8b 0d 90 01 04 88 14 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}