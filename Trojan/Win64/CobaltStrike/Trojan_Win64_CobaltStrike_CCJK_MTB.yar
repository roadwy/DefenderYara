
rule Trojan_Win64_CobaltStrike_CCJK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 89 c6 89 d8 83 e0 ?? 41 01 de 44 32 74 05 ?? 46 32 34 3b 48 3b 5d ?? 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}