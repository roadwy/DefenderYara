
rule Trojan_Win64_StealC_GVB_MTB{
	meta:
		description = "Trojan:Win64/StealC.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 c1 0f b6 c1 8a 84 04 90 01 00 00 48 63 4c 24 74 41 30 04 0f } //2
		$a_01_1 = {01 c1 0f b6 c1 8a 84 04 90 01 00 00 48 63 4c 24 74 49 89 df 30 04 0b } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}