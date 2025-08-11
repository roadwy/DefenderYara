
rule Trojan_Win64_Lazy_AS_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 33 c4 48 89 84 24 00 18 00 00 45 33 e4 44 89 a4 24 c0 00 00 00 c6 84 24 d0 00 00 00 ?? b0 ?? b1 ?? b2 ?? 41 b0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}