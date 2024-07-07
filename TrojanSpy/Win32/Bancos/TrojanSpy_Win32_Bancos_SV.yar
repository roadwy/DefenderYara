
rule TrojanSpy_Win32_Bancos_SV{
	meta:
		description = "TrojanSpy:Win32/Bancos.SV,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {0f b7 1a 0f bf 31 0f af de 81 c3 00 08 00 00 8b 74 24 24 c1 fb 0c 83 c1 02 89 1e 83 c2 02 83 44 24 24 04 40 83 f8 40 7c d7 } //2
		$a_01_1 = {c1 e5 0d 33 cd 03 d9 03 cb 8b eb c1 ed 11 33 dd 03 c3 03 d8 8b e8 c1 e5 09 33 c5 } //2
		$a_01_2 = {2d 2d 2d 2d 49 4e 46 4f 20 53 41 46 52 41 2d 2d 2d 2d } //1 ----INFO SAFRA----
		$a_01_3 = {2e 63 6f 6d 2e 62 72 2f 3f 73 65 6e 68 61 3d } //1 .com.br/?senha=
		$a_01_4 = {53 65 6e 68 61 54 65 63 6c 61 64 6f 56 61 72 } //1 SenhaTecladoVar
		$a_01_5 = {49 4e 4f 56 41 4e 44 4f 4f 4f 4f 2e 2e 2e } //1 INOVANDOOOO...
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}