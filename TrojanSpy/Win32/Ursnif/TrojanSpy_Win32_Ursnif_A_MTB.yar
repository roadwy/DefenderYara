
rule TrojanSpy_Win32_Ursnif_A_MTB{
	meta:
		description = "TrojanSpy:Win32/Ursnif.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {89 4c 24 20 8b d7 89 44 24 14 74 24 ff 44 24 10 8b 07 8a 4c 24 10 d3 c0 83 c7 04 33 c6 33 c3 8b f0 89 32 83 c2 04 ff 4c 24 14 75 e0 8b 4c 24 20 } //1
		$a_00_1 = {8a 04 0f 32 c3 88 01 41 4e 75 f5 } //1
		$a_01_2 = {76 65 72 73 69 6f 6e 3d 25 75 26 73 6f 66 74 3d 25 75 26 75 73 65 72 3d 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 26 73 65 72 76 65 72 3d 25 75 26 69 64 3d 25 75 26 74 79 70 65 3d 25 75 26 6e 61 6d 65 3d 25 73 } //1 version=%u&soft=%u&user=%08x%08x%08x%08x&server=%u&id=%u&type=%u&name=%s
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}