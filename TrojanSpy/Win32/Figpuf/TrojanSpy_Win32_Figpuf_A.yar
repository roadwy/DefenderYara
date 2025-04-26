
rule TrojanSpy_Win32_Figpuf_A{
	meta:
		description = "TrojanSpy:Win32/Figpuf.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {c1 e8 08 33 04 95 } //1
		$a_03_1 = {6a 0d ff 15 ?? ?? ?? ?? 89 47 28 3b c6 75 22 } //1
		$a_03_2 = {83 f9 22 0f 87 ?? ?? 00 00 74 7c 8b c1 83 e8 08 74 6c 48 74 60 } //1
		$a_01_3 = {8a 00 85 c9 75 04 8b ca eb 02 03 ce 32 01 88 45 e8 } //1
		$a_03_4 = {68 00 28 00 00 8d 85 24 d7 ff ff 50 56 ff 15 ?? ?? ?? ?? 85 c0 7f e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=3
 
}