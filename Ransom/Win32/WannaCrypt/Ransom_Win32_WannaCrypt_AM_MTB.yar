
rule Ransom_Win32_WannaCrypt_AM_MTB{
	meta:
		description = "Ransom:Win32/WannaCrypt.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 d8 1b c0 89 7c 94 10 25 44 88 00 00 05 60 40 00 00 8b c8 8b d9 c1 e9 02 f3 a5 8b cb 83 e1 03 f3 a4 8b 74 94 10 03 f0 89 74 94 10 42 83 fa 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}