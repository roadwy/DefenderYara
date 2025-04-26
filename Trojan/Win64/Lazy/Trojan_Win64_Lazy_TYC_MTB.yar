
rule Trojan_Win64_Lazy_TYC_MTB{
	meta:
		description = "Trojan:Win64/Lazy.TYC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e1 c1 ea 04 0f be c2 6b d0 34 0f b6 c1 ff c1 2a c2 04 ?? 41 30 40 ff 83 f9 0c 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}