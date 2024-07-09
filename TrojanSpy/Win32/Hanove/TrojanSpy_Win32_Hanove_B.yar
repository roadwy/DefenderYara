
rule TrojanSpy_Win32_Hanove_B{
	meta:
		description = "TrojanSpy:Win32/Hanove.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {80 38 00 74 08 fe 08 40 80 38 00 75 f8 c3 } //1
		$a_03_1 = {00 48 6f 73 74 3a 20 00 [0-40] 2f 71 69 71 00 } //1
		$a_01_2 = {3f 63 64 61 74 61 3d 00 26 64 65 74 61 69 6c 3d 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}