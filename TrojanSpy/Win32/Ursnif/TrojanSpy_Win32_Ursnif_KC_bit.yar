
rule TrojanSpy_Win32_Ursnif_KC_bit{
	meta:
		description = "TrojanSpy:Win32/Ursnif.KC!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 0e 0f b6 d0 0f b6 c9 33 d1 83 e2 0f c1 e8 04 33 04 95 90 01 04 c1 e9 04 8b d0 83 e2 0f 4f 33 ca c1 e8 04 46 33 04 8d 90 01 04 85 ff 75 cf 90 00 } //01 00 
		$a_01_1 = {76 65 72 73 69 6f 6e 3d 25 75 26 73 6f 66 74 3d 25 75 26 75 73 65 72 3d 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 26 73 65 72 76 65 72 3d 25 75 26 69 64 3d 25 75 26 74 79 70 65 3d 25 75 26 6e 61 6d 65 3d 25 73 } //00 00 
	condition:
		any of ($a_*)
 
}