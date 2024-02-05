
rule TrojanSpy_Win32_Ursnif_ANN_MTB{
	meta:
		description = "TrojanSpy:Win32/Ursnif.ANN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 c7 c0 d2 5e 01 89 bc 18 90 01 04 0f b6 05 90 01 04 89 3d 90 01 04 0f b6 3d 90 01 04 03 c7 3d 90 01 04 a0 90 01 04 75 90 00 } //01 00 
		$a_02_1 = {81 c3 04 67 82 01 8b 44 24 1c 03 d7 83 44 24 1c 04 89 15 90 01 04 8b 15 90 01 04 89 9c 02 90 01 04 8b 44 24 18 8b 15 90 01 04 83 c0 03 03 c2 81 7c 24 90 01 05 89 44 24 90 01 01 0f 82 90 00 } //01 00 
		$a_00_2 = {81 c7 0c b5 84 01 0f b7 d2 89 bc 18 5e e0 ff ff 0f b7 c2 83 c3 04 81 fb b2 20 00 00 8d 44 28 ff 89 5c 24 10 0f 82 } //00 00 
	condition:
		any of ($a_*)
 
}