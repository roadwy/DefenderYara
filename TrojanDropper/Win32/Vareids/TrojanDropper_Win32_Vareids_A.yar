
rule TrojanDropper_Win32_Vareids_A{
	meta:
		description = "TrojanDropper:Win32/Vareids.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 46 24 20 00 00 e0 8b 4f 28 2b 4e 0c 89 5d fc 8b 5d f8 81 e9 } //2
		$a_03_1 = {58 ab e2 fc 8b 7c 24 14 83 c4 14 5a 8d aa ?? ?? ?? ?? 55 } //2
		$a_01_2 = {03 f8 0f b7 47 06 40 40 6b c0 05 03 47 74 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=3
 
}