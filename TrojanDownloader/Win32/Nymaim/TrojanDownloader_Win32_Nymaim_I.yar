
rule TrojanDownloader_Win32_Nymaim_I{
	meta:
		description = "TrojanDownloader:Win32/Nymaim.I,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 08 00 "
		
	strings :
		$a_03_0 = {ff 75 08 c3 90 09 0c 00 8d 15 90 01 04 52 68 90 00 } //01 00 
		$a_03_1 = {33 ff 8d b4 7d 90 01 01 ff ff ff 0f b7 90 01 01 90 02 01 e8 90 01 04 a3 90 01 04 8b c7 99 6a 19 59 f7 f9 8d 42 61 66 89 06 0f b7 c0 50 e8 90 01 04 90 02 04 a3 90 1b 04 83 ff 40 72 90 00 } //01 00 
		$a_03_2 = {33 f6 8d 8c 75 90 01 01 ff ff ff 0f b7 90 01 01 90 02 01 e8 90 01 04 a3 90 01 04 90 02 03 8b c6 99 6a 19 5f f7 ff 8d 42 61 66 89 01 0f b7 90 02 02 e8 90 01 04 90 02 03 46 a3 90 1b 04 83 fe 40 72 90 00 } //01 00 
		$a_03_3 = {33 f6 8d 4c 35 90 01 01 0f be 01 90 02 01 e8 90 01 04 a3 90 01 04 8b c6 99 6a 19 5f f7 ff 80 c2 61 0f be c2 50 88 11 e8 90 01 04 46 59 90 02 01 a3 90 1b 03 83 fe 40 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}