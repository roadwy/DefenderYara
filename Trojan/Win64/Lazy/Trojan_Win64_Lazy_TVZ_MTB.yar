
rule Trojan_Win64_Lazy_TVZ_MTB{
	meta:
		description = "Trojan:Win64/Lazy.TVZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 f7 12 da 4b 41 f7 e8 c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 ?? 41 0f b6 c0 2a c1 04 34 41 30 02 41 ff c0 4d 8d 52 01 41 83 f8 13 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}