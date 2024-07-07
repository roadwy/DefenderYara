
rule Trojan_Win32_SmokeLoader_CU_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 04 89 44 24 10 8b 44 24 28 01 44 24 10 8b ce c1 e9 05 03 cb 8d 14 37 31 54 24 10 c7 05 90 02 04 19 36 6b ff c7 05 90 02 04 ff ff ff ff 89 4c 24 14 8b 44 24 14 31 44 24 10 8b 44 24 10 29 44 24 18 81 3d 90 02 04 93 00 00 00 75 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}