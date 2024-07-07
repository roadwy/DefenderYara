
rule Trojan_Win32_SmokeLoader_CL_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 14 33 44 24 10 c7 05 90 02 04 00 00 00 00 2b f0 89 44 24 14 8b c6 c1 e0 04 89 44 24 10 8b 44 24 24 01 44 24 10 8b c6 c1 e8 05 03 44 24 28 8d 0c 37 33 c8 8b 44 24 10 33 c1 2b d8 81 c7 47 86 c8 61 ff 4c 24 18 c7 05 90 02 04 19 36 6b ff c7 05 90 02 04 ff ff ff ff 0f 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}