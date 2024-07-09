
rule TrojanDropper_Win32_Nonaco_C{
	meta:
		description = "TrojanDropper:Win32/Nonaco.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 12 8b c3 99 6a 05 59 f7 f9 b0 fe 2a c2 d0 e0 00 44 1c 10 } //2
		$a_03_1 = {ff d7 6a 14 59 33 d2 f7 f1 8b 35 ?? ?? 40 00 } //2
		$a_01_2 = {f7 f1 52 ff d6 ff d7 50 53 6a 11 ff 15 } //2
		$a_01_3 = {74 6d 70 32 2e 72 65 67 00 3c 53 65 61 72 63 68 } //1 浴㉰爮来㰀敓牡档
		$a_01_4 = {72 65 67 25 73 20 22 25 73 22 00 } //1
		$a_01_5 = {72 65 25 73 20 22 25 73 22 00 } //1 敲猥∠猥"
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}