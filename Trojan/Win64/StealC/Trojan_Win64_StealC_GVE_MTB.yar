
rule Trojan_Win64_StealC_GVE_MTB{
	meta:
		description = "Trojan:Win64/StealC.GVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 c1 e1 02 45 01 c8 45 89 c0 44 89 c2 44 0f b6 04 10 44 31 c1 41 88 ca } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}