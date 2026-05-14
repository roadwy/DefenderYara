
rule Trojan_Win64_Lazy_LRB_MTB{
	meta:
		description = "Trojan:Win64/Lazy.LRB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 2b d1 41 83 c2 5f 45 0f b6 d2 45 33 c2 45 0f b7 c0 66 44 89 44 50 10 ff c1 3b f1 } //20
	condition:
		((#a_01_0  & 1)*20) >=20
 
}