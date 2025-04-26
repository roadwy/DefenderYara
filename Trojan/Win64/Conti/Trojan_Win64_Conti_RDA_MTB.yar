
rule Trojan_Win64_Conti_RDA_MTB{
	meta:
		description = "Trojan:Win64/Conti.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 85 e8 00 00 00 8d 44 00 3f 99 b9 7f 00 00 00 f7 f9 8b c2 48 8d a5 c8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}