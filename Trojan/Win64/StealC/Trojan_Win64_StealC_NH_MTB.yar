
rule Trojan_Win64_StealC_NH_MTB{
	meta:
		description = "Trojan:Win64/StealC.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 31 d3 48 83 f9 05 0f 83 7d 01 00 00 48 89 1c c8 eb 9f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}