
rule Trojan_Win64_Lazy_AMAD_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AMAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 09 33 c8 8b c1 e9 [0-1e] 88 01 8b 44 24 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Lazy_AMAD_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.AMAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 08 43 8d 14 10 0f b6 c1 4d 8d 40 ?? 34 ?? 80 e9 ?? f6 c2 ?? 0f b6 c0 0f b6 c9 0f 45 c8 4b 8d 04 02 43 88 4c 18 ?? 49 3b c1 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}