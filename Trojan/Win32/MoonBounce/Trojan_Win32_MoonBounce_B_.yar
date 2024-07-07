
rule Trojan_Win32_MoonBounce_B_{
	meta:
		description = "Trojan:Win32/MoonBounce.B!!MoonBounce.B,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {6a 04 03 f0 68 00 20 00 00 ff 76 50 ff 76 34 ff 57 08 } //1
		$a_01_1 = {6a 04 68 00 20 00 00 ff 76 50 50 ff 57 08 } //1
		$a_01_2 = {f7 ff 83 c7 71 6a 07 8d 04 88 8b d0 83 e2 07 c1 e8 03 0f b6 84 30 c8 00 00 00 } //1
		$a_01_3 = {8d 86 e0 01 00 00 50 8d 86 c0 01 00 00 50 8d 86 80 01 00 00 50 8d 86 1c 01 00 00 50 56 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}