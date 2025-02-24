
rule Trojan_Win64_Zusy_YAC_MTB{
	meta:
		description = "Trojan:Win64/Zusy.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 ff c0 48 f7 e1 48 c1 ea ?? 48 6b c2 ?? 48 2b c8 49 0f af cf 8a 44 0d ?? 43 32 04 0a 41 88 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}