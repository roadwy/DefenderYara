
rule TrojanSpy_Win32_Bradop_B{
	meta:
		description = "TrojanSpy:Win32/Bradop.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {54 41 52 47 55 53 00 90 09 08 00 ff ff ff ff 06 00 00 00 90 00 } //01 00 
		$a_01_1 = {c6 45 dc 0b 8d 8d 4c ff ff ff b2 11 8b c6 } //01 00 
		$a_03_2 = {ff 53 60 6a 00 8b 45 90 01 01 0f b6 50 90 01 01 b1 09 8b 45 90 1b 00 e8 90 01 04 8d 45 90 01 01 8b 15 90 01 04 8b 12 e8 90 01 04 ba d0 07 00 00 90 00 } //01 00 
		$a_03_3 = {8b 45 ec 8b 55 f4 89 90 90 5c 02 00 00 c7 80 58 02 00 00 90 01 04 8b 45 f8 8b 15 90 01 04 8b 12 e8 90 01 04 74 1c b2 01 8b 45 ec e8 90 01 04 8b 45 ec 05 70 02 00 00 90 00 } //01 00 
		$a_02_4 = {8b 45 e8 0f b6 50 90 04 01 02 0c 10 b1 07 8b 45 e8 e8 90 01 04 90 02 15 ba e8 03 00 00 8b 45 e8 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}