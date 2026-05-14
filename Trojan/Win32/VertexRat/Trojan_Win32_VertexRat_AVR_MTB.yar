
rule Trojan_Win32_VertexRat_AVR_MTB{
	meta:
		description = "Trojan:Win32/VertexRat.AVR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {50 b8 80 e5 41 00 8d b4 24 20 01 00 00 c6 84 24 b4 03 00 00 0a e8 ?? ?? ?? ?? 83 c4 04 8b c8 8d 84 24 e4 00 00 00 50 8b 44 24 1c c6 84 24 b4 03 00 00 0b e8 ?? ?? ?? ?? 83 c4 04 50 b8 6c e5 41 00 } //2
		$a_03_1 = {52 6a 00 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 ff d6 8d 45 f0 50 6a 00 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 ff d6 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}