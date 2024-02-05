
rule TrojanDownloader_Win32_Zusy_SIB_MTB{
	meta:
		description = "TrojanDownloader:Win32/Zusy.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d 08 83 c1 01 89 4d 08 8b 55 08 0f be 02 85 c0 74 90 01 01 8b 4d 08 8a 11 80 c2 90 01 01 8b 45 08 88 10 90 00 } //01 00 
		$a_03_1 = {83 c0 01 89 45 90 01 01 8b 4d 90 1b 00 3b 0d 90 01 04 73 90 01 01 8b 15 90 01 04 03 55 90 1b 00 0f b6 02 33 05 90 01 04 03 05 90 01 04 8b 0d 90 1b 04 03 4d 90 1b 00 88 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}