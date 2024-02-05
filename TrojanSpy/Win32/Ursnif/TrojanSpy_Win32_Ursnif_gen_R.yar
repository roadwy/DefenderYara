
rule TrojanSpy_Win32_Ursnif_gen_R{
	meta:
		description = "TrojanSpy:Win32/Ursnif.gen!R,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 3d 4a 31 74 17 0f b7 46 14 83 c6 14 66 85 c0 75 ee } //01 00 
		$a_01_1 = {8b 31 8d 51 08 8b 0a 83 c1 01 81 e1 fe 00 00 00 ff 34 ca e2 fb } //01 00 
		$a_00_2 = {66 81 78 04 64 86 75 08 8b 80 88 00 00 00 eb 03 8b 40 78 } //01 00 
		$a_01_3 = {43 8a cb d3 c0 33 c6 33 45 0c 8b f0 89 32 83 c2 04 ff 4d 08 75 d3 } //00 00 
	condition:
		any of ($a_*)
 
}