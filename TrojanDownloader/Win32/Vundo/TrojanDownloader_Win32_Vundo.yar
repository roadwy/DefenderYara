
rule TrojanDownloader_Win32_Vundo{
	meta:
		description = "TrojanDownloader:Win32/Vundo,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 43 60 bf 8b 0d f8 6c 40 00 c6 43 65 90 89 4b 61 } //01 00 
		$a_01_1 = {89 35 3c 68 40 00 a3 2c 68 40 00 72 c1 8b 15 5c 6c 40 00 8d 83 c2 02 00 00 8d 8b 72 02 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}