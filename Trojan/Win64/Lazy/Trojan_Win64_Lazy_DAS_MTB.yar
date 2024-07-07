
rule Trojan_Win64_Lazy_DAS_MTB{
	meta:
		description = "Trojan:Win64/Lazy.DAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 74 24 27 90 01 01 34 90 01 01 c6 44 24 20 30 88 44 24 28 48 8d 44 24 20 49 ff c0 42 80 3c 00 00 75 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}