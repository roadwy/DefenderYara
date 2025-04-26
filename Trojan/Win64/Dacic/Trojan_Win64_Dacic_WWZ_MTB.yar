
rule Trojan_Win64_Dacic_WWZ_MTB{
	meta:
		description = "Trojan:Win64/Dacic.WWZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e1 8b c1 2b c2 d1 e8 03 c2 c1 e8 05 0f be c0 6b d0 38 0f b6 c1 ff c1 2a c2 04 36 41 30 40 ?? 83 f9 0c 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}