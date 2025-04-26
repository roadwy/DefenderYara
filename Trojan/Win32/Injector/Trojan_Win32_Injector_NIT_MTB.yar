
rule Trojan_Win32_Injector_NIT_MTB{
	meta:
		description = "Trojan:Win32/Injector.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {53 bb 6c d6 41 00 68 34 5e 40 00 e8 e0 ff ff ff 89 03 68 44 5e 40 00 8b 03 50 e8 d9 ff ff ff a3 b0 d6 41 00 68 54 5e 40 00 8b 03 50 e8 c7 ff ff ff a3 ac d6 41 00 68 68 5e 40 00 8b 03 50 e8 b5 ff ff ff a3 b4 d6 41 00 68 7c 5e 40 00 8b 03 50 e8 a3 ff ff ff a3 d0 d6 41 00 68 88 5e 40 00 8b 03 50 e8 91 ff ff ff a3 d8 d6 41 00 68 9c 5e 40 00 8b 03 50 e8 7f ff ff ff a3 e8 d6 41 00 68 b8 5e 40 00 8b 03 50 e8 6d ff ff ff a3 ec d6 41 00 68 c8 5e 40 00 8b 03 50 e8 5b ff ff ff a3 f0 d6 41 00 68 d8 5e 40 00 8b 03 50 e8 49 ff ff ff a3 f4 d6 41 00 68 e8 5e 40 00 8b 03 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}