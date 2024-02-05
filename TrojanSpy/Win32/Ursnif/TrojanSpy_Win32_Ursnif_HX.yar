
rule TrojanSpy_Win32_Ursnif_HX{
	meta:
		description = "TrojanSpy:Win32/Ursnif.HX,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 c8 04 00 00 50 89 44 24 28 89 44 24 2c 8d 44 24 30 50 83 cb ff c7 44 24 28 eb fe cc cc e8 90 01 04 83 c4 0c e8 90 01 04 8b f0 8d 44 24 08 50 ff 37 c7 44 24 58 03 00 10 00 90 00 } //0a 00 
		$a_01_1 = {8b 31 8d 51 08 8b 0a 83 c1 01 81 e1 fe 00 00 00 ff 34 ca e2 fb } //01 00 
		$a_03_2 = {68 d0 04 00 00 33 f6 8d 85 10 fb ff ff 56 50 e8 90 01 04 e8 90 01 04 8b 7b 0c 68 00 01 00 00 68 01 2b 00 10 89 45 f8 8d 8f 18 02 00 00 c7 85 40 fb ff ff 03 00 10 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}