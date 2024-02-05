
rule TrojanDownloader_Win32_Razy_MA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Razy.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 05 f4 1f 39 01 80 ff ff ff 0f 85 90 01 04 f7 05 f4 1f 39 01 ff ff ff ff 0f 85 90 01 04 e8 90 01 04 eb 90 00 } //01 00 
		$a_00_1 = {33 35 d4 a3 57 00 33 35 d8 a3 57 00 33 35 dc a3 57 00 1b cf 33 35 e0 a3 57 00 33 35 e4 a3 57 00 33 35 e8 a3 57 00 c0 d6 fc 33 35 ec a3 57 00 f9 33 35 f0 a3 57 00 66 d3 c9 c0 de 97 33 35 f4 a3 57 00 80 fb 10 3b fc 33 35 } //01 00 
		$a_01_2 = {47 65 74 44 69 73 6b 46 72 65 65 53 70 61 63 65 } //01 00 
		$a_01_3 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //01 00 
		$a_01_4 = {4c 6f 63 6b 46 69 6c 65 } //01 00 
		$a_01_5 = {55 6e 6d 61 70 56 69 65 77 4f 66 46 69 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}