
rule Trojan_Win32_SmokeLoader_CX_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d6 c1 ea 05 03 ce c7 05 [0-04] 19 36 6b ff c7 05 [0-04] ff ff ff ff 89 54 24 14 8b 44 24 2c 01 44 24 14 31 4c 24 0c 8b 44 24 14 31 44 24 0c 8b 44 24 0c 29 44 24 10 81 3d [0-04] 93 00 00 00 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}