
rule Trojan_Win64_LummaC_AMCZ_MTB{
	meta:
		description = "Trojan:Win64/LummaC.AMCZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 0f bf c2 c1 ea ?? 41 c1 f8 ?? 41 01 d0 44 89 c2 c1 e2 ?? 41 29 d0 44 01 c1 81 c1 ?? ?? ?? ?? 8d 51 ?? 66 83 f9 ?? 0f b6 d2 0f 42 d1 88 94 05 ?? ?? ?? ?? 48 ff c0 48 83 f8 ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}