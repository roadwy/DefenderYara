
rule Trojan_Win32_Injector_ABI_MTB{
	meta:
		description = "Trojan:Win32/Injector.ABI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b c1 66 87 d2 66 0b d2 80 ee c0 2b f1 8b 4d c8 66 0f a3 da 66 8b d1 f8 66 c1 ea 05 66 2b ca 66 0f bc d1 f6 da 66 0f c1 d2 8b 55 f4 85 ca 81 fd e9 47 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}