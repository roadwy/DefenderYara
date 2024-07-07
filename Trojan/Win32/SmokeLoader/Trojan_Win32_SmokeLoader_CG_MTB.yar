
rule Trojan_Win32_SmokeLoader_CG_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 10 33 44 24 28 c7 05 90 02 04 00 00 00 00 2b d0 8b ca c1 e1 04 89 44 24 10 89 4c 24 28 8b 44 24 1c 01 44 24 28 8b c2 c1 e8 05 03 c5 8d 0c 17 33 c8 8b 44 24 28 33 c1 2b f0 81 c7 90 02 04 4b c7 05 90 02 04 19 36 6b ff c7 05 90 02 04 ff ff ff ff 0f 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}