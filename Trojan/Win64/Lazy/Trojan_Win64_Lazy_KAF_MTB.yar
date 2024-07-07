
rule Trojan_Win64_Lazy_KAF_MTB{
	meta:
		description = "Trojan:Win64/Lazy.KAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 00 0f b7 8c 24 90 01 04 33 c1 0f b7 8c 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}