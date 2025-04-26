
rule Trojan_Win64_LummaC_YAP_MTB{
	meta:
		description = "Trojan:Win64/LummaC.YAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 01 00 00 "
		
	strings :
		$a_03_0 = {43 02 04 37 0f b6 c0 41 8a 04 07 4c 8b 7d ?? 48 8b 4d ?? 4c 8b 75 ?? 42 32 04 31 42 88 04 31 } //11
	condition:
		((#a_03_0  & 1)*11) >=11
 
}