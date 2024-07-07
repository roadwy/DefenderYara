
rule Trojan_Win64_StealC_KAD_MTB{
	meta:
		description = "Trojan:Win64/StealC.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {76 04 80 6d 90 01 02 8b 45 90 01 01 c1 e0 90 01 01 89 c2 8b 45 90 01 01 01 c2 0f b6 45 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}