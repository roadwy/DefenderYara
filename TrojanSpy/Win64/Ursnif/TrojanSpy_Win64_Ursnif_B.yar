
rule TrojanSpy_Win64_Ursnif_B{
	meta:
		description = "TrojanSpy:Win64/Ursnif.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {3f 76 65 72 73 69 6f 6e 3d 25 75 26 75 73 65 72 3d 25 78 25 78 25 78 25 78 26 73 65 72 76 65 72 3d 25 75 26 69 64 3d 25 75 } //1 ?version=%u&user=%x%x%x%x&server=%u&id=%u
		$a_03_1 = {b9 ff 03 1f 00 ff 15 90 01 04 48 85 c0 48 8b f8 74 18 45 33 c0 48 8b d0 48 8b ce ff 15 90 01 04 48 8b cf ff 15 90 01 04 48 8d 54 24 90 01 01 48 8b cb e8 90 01 04 85 c0 75 90 01 01 48 8b cb ff 15 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}