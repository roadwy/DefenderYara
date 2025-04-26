
rule Trojan_Win32_Kuluoz_gen_A{
	meta:
		description = "Trojan:Win32/Kuluoz.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {5e 5b 61 2d 7a 41 2d 5a 5d 3a 2e 2a 5c 5c 28 2e 2a 29 24 } //2 ^[a-zA-Z]:.*\\(.*)$
		$a_03_1 = {83 c4 0c 81 bc 24 ?? ?? 00 00 00 00 20 03 0f 8d ?? ?? 00 00 8d 84 24 ?? ?? 00 00 e8 ?? ?? ?? ?? 03 84 24 ?? ?? 00 00 3d 00 00 20 03 0f 86 } //1
		$a_03_2 = {83 c4 18 81 bd ?? ?? ff ff 00 00 20 03 0f 8d ?? ?? 00 00 8b 85 ?? ?? ff ff 8a c8 f6 d1 80 e1 01 88 8d ?? ?? ff ff 0f 85 ?? ?? 00 00 8b 8d ?? ?? ff ff 85 c9 0f 84 ?? ?? 00 00 c1 e8 02 a8 01 74 ?? 8b 11 8b 42 34 ff d0 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}