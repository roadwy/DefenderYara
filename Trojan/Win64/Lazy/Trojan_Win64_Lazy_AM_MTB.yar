
rule Trojan_Win64_Lazy_AM_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c2 f7 d2 89 d5 09 cd f7 d5 83 e2 ?? 25 ?? 00 00 00 09 d0 31 c8 83 f0 ?? 21 c8 89 e9 21 c1 31 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}