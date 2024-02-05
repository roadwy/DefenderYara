
rule TrojanSpy_Win32_Ursnif_HS{
	meta:
		description = "TrojanSpy:Win32/Ursnif.HS,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 08 00 "
		
	strings :
		$a_03_0 = {3d 40 71 61 ea 74 90 01 01 3d d8 e8 ba 1e 90 00 } //01 00 
		$a_01_1 = {43 8a cb d3 c0 33 c6 33 45 0c 8b f0 89 32 83 c2 04 ff 4d 08 75 ce } //01 00 
		$a_01_2 = {8b 31 8d 51 08 8b 0a 83 c1 01 81 e1 fe 00 00 00 ff 34 ca e2 fb } //00 00 
		$a_00_3 = {87 10 00 00 55 27 98 1a } //1c c6 
	condition:
		any of ($a_*)
 
}