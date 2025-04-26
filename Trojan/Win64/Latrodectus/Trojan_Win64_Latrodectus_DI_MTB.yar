
rule Trojan_Win64_Latrodectus_DI_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.DI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 4c 24 ?? 33 d2 48 8b c1 b9 1a 00 00 00 48 f7 f1 48 8b c2 0f b6 84 04 [0-04] 8b 4c 24 ?? 33 c8 8b c1 48 63 4c 24 ?? 48 8b 54 24 ?? 88 04 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}