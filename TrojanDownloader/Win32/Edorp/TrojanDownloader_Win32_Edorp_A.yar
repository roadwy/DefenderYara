
rule TrojanDownloader_Win32_Edorp_A{
	meta:
		description = "TrojanDownloader:Win32/Edorp.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 44 24 08 3f 00 0f 00 a1 90 01 04 8b 84 85 90 01 02 ff ff 89 44 24 04 8b 45 f4 89 04 24 e8 90 01 04 83 ec 0c 89 45 f0 90 00 } //01 00 
		$a_03_1 = {8d 85 78 ff ff ff 89 44 24 08 a1 90 01 04 8b 04 85 90 01 04 89 44 24 04 8d 85 68 ff ff ff 89 04 24 c7 85 28 ff ff ff 12 00 00 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}