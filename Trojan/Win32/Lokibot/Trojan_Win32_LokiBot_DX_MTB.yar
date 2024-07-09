
rule Trojan_Win32_LokiBot_DX_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {f6 d9 c0 c1 02 2a c8 80 f1 d1 c0 c1 02 f6 d9 c0 c1 03 2a c8 f6 d1 80 e9 21 80 f1 6e 2a c8 88 88 [0-04] 40 3d ?? ?? ?? ?? 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_LokiBot_DX_MTB_2{
	meta:
		description = "Trojan:Win32/LokiBot.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 e0 5e 00 00 [0-08] 66 81 f9 3f de 83 e9 04 [0-08] 8b 1c 0f [0-25] 31 f3 [0-30] 09 1c 08 [0-10] 7f [0-08] 89 c6 [0-10] c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}