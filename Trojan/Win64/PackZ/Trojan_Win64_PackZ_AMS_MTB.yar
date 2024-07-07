
rule Trojan_Win64_PackZ_AMS_MTB{
	meta:
		description = "Trojan:Win64/PackZ.AMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 d1 01 ce 8b 13 bf 90 01 04 81 ef 90 01 04 81 e2 90 01 04 81 c6 90 01 04 01 f7 81 ef 90 01 04 31 10 09 f9 49 40 bf 90 01 04 81 e9 90 01 04 43 21 fe 89 f1 09 f9 81 f8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}