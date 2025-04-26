
rule Trojan_Win64_Lazy_VVZ_MTB{
	meta:
		description = "Trojan:Win64/Lazy.VVZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 1f 85 eb 51 4d 8d 40 01 f7 e1 c1 ea 04 0f be c2 6b d0 ?? 0f b6 c1 ff c1 2a c2 04 37 41 30 40 ff 83 f9 04 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}