
rule Trojan_Win64_CobaltStrike_CM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {29 c3 0f af d8 f6 c3 01 0f 94 c0 08 c1 89 d3 30 cb 30 c2 30 c1 80 f2 01 08 da 38 d1 0f 85 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}