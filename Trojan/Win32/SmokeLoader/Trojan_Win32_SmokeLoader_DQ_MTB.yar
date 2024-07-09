
rule Trojan_Win32_SmokeLoader_DQ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.DQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 05 c7 05 [0-04] 19 36 6b ff c7 05 [0-04] ff ff ff ff 89 44 24 14 8b 44 24 24 01 44 24 14 8b 4c 24 14 8b 44 24 10 33 cd 33 c1 89 44 24 10 2b d8 c7 44 24 18 00 00 00 00 8b 44 24 2c 01 44 24 18 2b 7c 24 18 ff 4c 24 1c 0f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}