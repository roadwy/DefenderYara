
rule Ransom_Win32_Dircrypt_E{
	meta:
		description = "Ransom:Win32/Dircrypt.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8b c6 f7 f7 49 8b f0 8a c2 04 30 83 fa 09 88 01 76 14 83 7c 24 18 00 0f 94 c0 fe c8 24 e0 04 61 } //1
		$a_00_1 = {2e 00 65 00 6e 00 63 00 2e 00 72 00 74 00 66 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}