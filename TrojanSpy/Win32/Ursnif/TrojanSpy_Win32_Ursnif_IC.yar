
rule TrojanSpy_Win32_Ursnif_IC{
	meta:
		description = "TrojanSpy:Win32/Ursnif.IC,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 65 74 65 72 6d 69 6e 65 5c 4f 70 70 6f 73 69 74 65 5c 73 65 74 74 6c 65 5c 42 65 66 6f 72 65 64 6f 75 62 6c 65 2e 70 64 62 00 } //1
		$a_01_1 = {4f 00 63 00 65 00 61 00 6e 00 68 00 6f 00 75 00 73 00 65 00 20 00 4d 00 65 00 64 00 69 00 61 00 20 00 53 00 63 00 69 00 65 00 6e 00 63 00 65 00 } //1 Oceanhouse Media Science
		$a_01_2 = {6f 00 76 00 65 00 72 00 74 00 68 00 65 00 73 00 65 00 2e 00 65 00 78 00 65 00 } //1 overthese.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanSpy_Win32_Ursnif_IC_2{
	meta:
		description = "TrojanSpy:Win32/Ursnif.IC,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 08 69 c9 0d 66 19 00 03 ce 88 4c 3a 08 47 89 08 83 ff 08 72 ea } //1
		$a_01_1 = {6b d2 28 81 f1 3a 5f 00 00 0f b7 c9 03 d0 89 4d f8 8d 74 16 40 eb 08 } //1
		$a_01_2 = {76 10 81 78 fb 5c 4c 6f 77 75 07 } //1
		$a_01_3 = {76 65 72 73 69 6f 6e 3d 25 75 26 73 6f 66 74 3d 25 75 26 75 73 65 72 3d 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 26 73 65 72 76 65 72 3d 25 75 26 69 64 3d 25 75 26 74 79 70 65 3d 25 75 26 6e 61 6d 65 3d 25 73 } //1 version=%u&soft=%u&user=%08x%08x%08x%08x&server=%u&id=%u&type=%u&name=%s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}