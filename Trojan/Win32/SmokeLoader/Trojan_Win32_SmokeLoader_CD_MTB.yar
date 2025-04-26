
rule Trojan_Win32_SmokeLoader_CD_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 10 33 44 24 30 c7 05 [0-04] 00 00 00 00 2b f0 8b ce c1 e1 04 89 44 24 10 89 4c 24 30 8b 44 24 20 01 44 24 30 8b c6 c1 e8 05 03 44 24 24 03 de 33 d8 8b 44 24 30 68 b9 79 37 9e 33 c3 8d 54 24 18 52 c7 05 [0-04] 19 36 6b ff c7 05 [0-04] ff ff ff ff 2b f8 e8 [0-04] 4d 0f } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}