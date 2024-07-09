
rule Trojan_Win32_SmokeLoader_CK_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 14 33 44 24 10 c7 05 [0-04] 00 00 00 00 2b d0 89 44 24 14 8b c2 c1 e0 04 89 44 24 10 8b 44 24 20 01 44 24 10 8b c2 c1 e8 05 03 c5 8d 0c 17 33 c8 8b 44 24 10 33 c1 2b f0 81 c7 47 86 c8 61 4b c7 05 [0-04] 19 36 6b ff c7 05 [0-04] ff ff ff ff 0f } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}