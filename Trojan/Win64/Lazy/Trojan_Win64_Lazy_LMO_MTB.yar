
rule Trojan_Win64_Lazy_LMO_MTB{
	meta:
		description = "Trojan:Win64/Lazy.LMO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 89 c8 31 d2 49 f7 f2 48 69 c0 7c ff ff ff 4c 01 d8 41 8a 04 01 42 30 04 09 49 ff c1 4d 39 c8 } //20
	condition:
		((#a_01_0  & 1)*20) >=20
 
}