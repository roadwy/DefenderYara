
rule TrojanSpy_Win32_Cutwail_gen_C{
	meta:
		description = "TrojanSpy:Win32/Cutwail.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {66 3d 19 00 74 14 33 c9 66 8b 0e 51 ff d7 66 3d 19 00 } //2
		$a_02_1 = {68 00 24 40 9c 56 ff 15 ?? ?? ?? ?? 56 } //2
		$a_00_2 = {64 61 74 61 3d 25 73 00 } //1 慤慴┽s
		$a_00_3 = {6d 61 69 6c 73 70 65 63 74 72 65 00 } //1 慭汩灳捥牴e
		$a_00_4 = {53 4d 54 50 44 52 56 00 } //1 䵓偔剄V
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}