
rule TrojanSpy_Win32_Hitpop_gen_C{
	meta:
		description = "TrojanSpy:Win32/Hitpop.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 54 0a ff e8 90 01 02 ff ff 8b 45 e0 e8 90 01 02 ff ff 8b 55 f0 0f b6 54 3a ff 33 c2 89 45 f8 8d 45 dc 8b 55 f8 e8 90 01 02 ff ff 8b 55 dc 8b c6 e8 90 01 02 ff ff 47 4b 75 b0 90 00 } //01 00 
		$a_03_1 = {8a 54 3a ff e8 90 01 02 ff ff 8b 45 e0 e8 90 01 02 ff ff 8b 55 f0 0f b6 54 32 ff 33 c2 89 45 f4 8d 45 dc 8b 55 f4 e8 90 01 02 ff ff 8b 55 dc 8b 45 f8 e8 06 e9 ff ff 8b 45 f8 46 4b 75 b4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}