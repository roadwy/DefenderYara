
rule Trojan_Win64_ZLoader_YAB_MTB{
	meta:
		description = "Trojan:Win64/ZLoader.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 15 48 2b c8 8a 44 0d ?? 43 32 04 02 41 88 00 } //11
	condition:
		((#a_03_0  & 1)*11) >=11
 
}