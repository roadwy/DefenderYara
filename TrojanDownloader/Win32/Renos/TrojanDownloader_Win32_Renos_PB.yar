
rule TrojanDownloader_Win32_Renos_PB{
	meta:
		description = "TrojanDownloader:Win32/Renos.PB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 74 10 ff 2b 90 02 08 a1 90 01 04 8b 55 f8 8a 44 10 ff 8b 55 fc 8b 4d f4 88 04 0a ff 45 f4 81 7d f8 90 01 04 0f 86 90 01 02 ff ff 90 00 } //01 00 
		$a_03_1 = {30 4c 10 ff 90 02 02 a1 90 01 04 8b 55 f8 8a 44 10 ff 8b 55 fc 8b 4d f4 88 04 0a ff 45 f4 81 7d f8 90 01 04 0f 86 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}