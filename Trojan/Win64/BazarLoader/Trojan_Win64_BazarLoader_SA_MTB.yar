
rule Trojan_Win64_BazarLoader_SA_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 f7 f1 0f b6 44 14 90 01 01 41 8b d0 33 d0 8b 8c 24 90 01 04 8b 84 24 90 01 04 03 c1 03 84 24 90 01 04 8b 4c 24 90 01 01 0f af 8c 24 90 01 04 03 c1 48 63 c8 48 8b 84 24 90 01 04 88 14 08 e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}