
rule Trojan_Win64_Lazy_AZL_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AZL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c8 c1 e9 1e 33 c8 69 c9 65 89 07 6c 03 ca 89 4c 95 94 8b c1 48 ff c2 49 3b d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}