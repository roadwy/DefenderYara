
rule TrojanDownloader_Win32_Buerak_G_MTB{
	meta:
		description = "TrojanDownloader:Win32/Buerak.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b f3 03 f1 34 1e 90 02 40 c1 c6 0b 90 02 40 83 c2 0d 33 15 90 00 } //01 00 
		$a_02_1 = {0f b7 59 06 34 1e 90 02 20 8d 49 04 90 02 40 8b c3 90 02 30 8b cf 83 e9 89 33 0d 90 00 } //01 00 
		$a_02_2 = {32 c1 e9 0b 90 02 30 89 3d 90 02 30 c7 05 90 02 40 0f b6 42 90 01 01 8b c3 90 02 30 c7 45 90 02 30 03 4c 24 90 02 30 0f b6 41 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}