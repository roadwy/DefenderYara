
rule TrojanDownloader_Win32_Chaneeks_A{
	meta:
		description = "TrojanDownloader:Win32/Chaneeks.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 86 57 0d 00 68 88 4e 0d 00 e8 1a 00 00 00 89 45 fc 68 fa 8b 34 00 68 88 4e 0d 00 } //01 00 
		$a_03_1 = {8d 44 24 04 8d 4c 24 00 50 51 e8 90 01 02 ff ff 83 c4 08 68 90 01 04 ff 54 24 04 68 90 01 04 89 44 24 90 01 01 ff 54 24 04 68 90 01 04 50 89 44 24 90 01 01 ff 54 24 0c 8b 54 24 90 01 01 68 90 01 04 52 89 44 24 90 01 01 ff 54 24 0c 89 44 24 90 01 01 8d 44 24 00 50 e8 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}