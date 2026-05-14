
rule Trojan_Win64_StealC_ABS_MTB{
	meta:
		description = "Trojan:Win64/StealC.ABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {29 fe 48 63 fe 0f b6 5c 3c 30 88 5c 04 30 88 54 3c 30 0f b6 44 04 30 01 d0 0f b6 c0 0f b6 44 04 30 48 63 54 24 10 30 04 11 8b 6c 24 10 83 c5 01 ba } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}