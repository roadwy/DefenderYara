
rule TrojanDownloader_Win32_Tiny_GP_MTB{
	meta:
		description = "TrojanDownloader:Win32/Tiny.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 8b ec 6a 90 02 01 68 90 02 04 68 90 02 04 e8 90 02 04 83 90 02 02 a3 90 02 04 6a 90 02 01 68 90 02 04 68 90 02 04 e8 90 02 04 83 90 02 02 a3 90 02 04 6a 90 02 01 68 90 02 04 68 90 02 04 e8 90 02 04 83 90 02 02 a3 90 02 04 6a 90 02 01 68 90 02 04 68 90 02 04 e8 90 02 04 83 90 02 02 a3 90 02 04 6a 90 00 } //01 00 
		$a_02_1 = {8b c8 8b 45 90 02 01 99 f7 f9 8b 45 90 02 01 0f be 90 02 02 33 d9 8b 55 90 02 01 03 55 90 02 01 88 1a eb 90 0a 3c 00 8b 4d 90 02 01 03 4d 90 02 01 0f be 90 02 01 8b 55 90 02 01 52 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}