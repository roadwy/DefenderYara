
rule Trojan_Win64_Lazy_SOK_MTB{
	meta:
		description = "Trojan:Win64/Lazy.SOK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 eb 03 d3 c1 fa 05 8b c2 c1 e8 ?? 03 d0 0f be c2 6b c8 33 0f b6 c3 ff c3 2a c1 04 37 41 30 40 ff 83 fb 17 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}