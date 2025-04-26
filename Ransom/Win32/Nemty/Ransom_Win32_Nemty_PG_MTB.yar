
rule Ransom_Win32_Nemty_PG_MTB{
	meta:
		description = "Ransom:Win32/Nemty.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {f7 d0 05 b8 00 00 00 8b c8 c1 e9 04 83 e1 0f c1 e0 04 0b c8 81 e1 ff 00 00 00 f7 d1 2b ca 33 ca 2b ca 8b c1 c1 e8 06 83 e0 03 c1 e1 02 0b c1 83 f0 1a 25 ff 00 00 00 33 c2 8b c8 d1 e9 80 e1 7f c0 e0 07 0a c8 88 8a ?? ?? ?? ?? 42 81 fa ?? ?? 00 00 72 90 09 0e 00 0f b6 82 ?? ?? ?? ?? 8d 84 10 } //1
		$a_02_1 = {33 c0 8a 81 ?? ?? ?? ?? f7 d0 48 8b d0 83 e0 01 d1 ea 83 e2 7f c1 e0 07 0b d0 f7 d2 33 d1 8d 44 0a 1f f7 d0 35 c0 00 00 00 8d 54 48 01 f7 d2 8d 44 0a 30 88 81 e0 20 46 00 41 81 f9 ?? ?? 00 00 72 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}