
rule Trojan_Win32_SmokeLoader_CPVV_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CPVV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 44 24 14 8b c6 c1 e0 ?? 89 44 24 10 8b 44 24 28 01 44 24 10 8b 44 24 18 8b d6 c1 ea ?? 03 d5 03 c6 31 44 24 10 c7 05 [0-0a] c7 05 [0-0a] 89 54 24 14 8b 44 24 14 31 44 24 10 8b 44 24 10 29 44 24 1c 8b 44 24 2c 29 44 24 18 4b 0f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}