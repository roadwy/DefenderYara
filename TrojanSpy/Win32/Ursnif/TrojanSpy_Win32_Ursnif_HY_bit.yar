
rule TrojanSpy_Win32_Ursnif_HY_bit{
	meta:
		description = "TrojanSpy:Win32/Ursnif.HY!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 10 3b 55 ?? 75 0a 8b 50 04 3b 55 ?? 75 02 8b d8 83 c0 28 49 74 04 85 db 74 e5 } //1
		$a_03_1 = {8b 16 85 d2 89 55 ?? 74 19 ff 45 08 8a 4d 08 33 d7 8b 7d ?? 33 d0 d3 ca 89 16 83 c6 04 ff 4d f4 75 de } //1
		$a_01_2 = {8b 0a 83 c1 01 81 e1 fe 00 00 00 ff 34 ca e2 fb } //1
		$a_03_3 = {68 c8 04 00 00 50 89 44 24 28 89 44 24 2c 8d 44 24 30 50 83 cb ff c7 44 24 28 eb fe cc cc e8 ?? ?? ?? ?? 83 c4 0c e8 ?? ?? ?? ?? 8b f0 8d 44 24 08 50 ff 37 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}