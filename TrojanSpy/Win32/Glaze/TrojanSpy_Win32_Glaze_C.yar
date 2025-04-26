
rule TrojanSpy_Win32_Glaze_C{
	meta:
		description = "TrojanSpy:Win32/Glaze.C,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0b 00 05 00 00 "
		
	strings :
		$a_03_0 = {8a 14 08 80 f2 ?? 88 11 41 4f 75 f4 } //5
		$a_03_1 = {8a 08 84 c9 74 08 80 f1 ?? 88 08 40 eb f2 } //5
		$a_03_2 = {66 3d 15 00 0f 85 ?? 00 00 00 53 ff 76 04 ff 15 ?? ?? 00 10 80 a5 ?? ff ff ff 00 6a 31 8b d8 59 33 c0 8d bd ?? ff ff ff f3 ab 66 ab aa 8d 85 ?? ff ff ff } //10
		$a_01_3 = {61 6c 6f 67 2e 74 78 74 00 } //1
		$a_01_4 = {57 53 50 53 74 61 72 74 75 70 00 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=11
 
}