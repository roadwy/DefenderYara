
rule Trojan_Win32_SmokeLoader_CR_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 24 01 44 24 14 8b 44 24 14 33 c3 33 44 24 10 c7 05 [0-04] 00 00 00 00 2b f0 89 44 24 14 8b c6 c1 e0 04 89 44 24 10 8b 44 24 28 01 44 24 10 8b ce c1 e9 05 03 cd 8d 14 37 31 54 24 10 c7 05 [0-04] 19 36 6b ff c7 05 [0-04] ff ff ff ff 89 4c 24 14 8b 44 24 14 31 44 24 10 8b 44 24 10 29 44 24 18 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}