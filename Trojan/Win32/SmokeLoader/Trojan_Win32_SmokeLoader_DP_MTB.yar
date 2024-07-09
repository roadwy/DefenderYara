
rule Trojan_Win32_SmokeLoader_DP_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.DP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 05 c7 05 [0-04] 19 36 6b ff c7 05 [0-04] ff ff ff ff 89 44 24 14 8b 44 24 24 01 44 24 14 8b 4c 24 14 8b 44 24 10 33 cb 33 c1 2b f8 8d 44 24 1c e8 [0-04] ff 4c 24 18 0f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}