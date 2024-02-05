
rule TrojanDownloader_Win32_Banload_BFX{
	meta:
		description = "TrojanDownloader:Win32/Banload.BFX,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {54 61 62 4f 72 64 65 72 90 01 03 54 65 78 74 90 01 02 68 74 74 70 90 02 01 3a 2f 2f 90 00 } //01 00 
		$a_03_1 = {83 c0 50 e8 90 01 04 6a 00 b9 bf 28 00 00 ba 90 01 04 8b 83 90 01 02 00 00 90 00 } //01 00 
		$a_03_2 = {84 c0 74 05 e8 90 01 04 e8 90 01 02 ff ff 33 c0 e8 90 01 02 ff ff 84 c0 0f 84 90 01 02 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}