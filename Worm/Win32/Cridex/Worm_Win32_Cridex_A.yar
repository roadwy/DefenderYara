
rule Worm_Win32_Cridex_A{
	meta:
		description = "Worm:Win32/Cridex.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {73 68 65 6c 6c 5c [0-08] 5c 63 6f 6d 6d 61 6e 64 3d 25 53 } //1
		$a_03_1 = {68 01 00 00 80 e8 ?? ?? ?? ?? 83 c4 24 85 c0 75 c0 e8 ?? ?? ?? ?? 33 c0 } //1
		$a_03_2 = {c1 e2 10 0b d1 89 15 ?? ?? ?? ?? 0f b7 94 24 ?? ?? 00 00 c1 e2 10 0b d0 89 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 d2 b9 e8 03 00 00 f7 f1 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}