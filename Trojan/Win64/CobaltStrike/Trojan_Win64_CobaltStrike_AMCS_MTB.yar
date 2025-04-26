
rule Trojan_Win64_CobaltStrike_AMCS_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AMCS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 89 c1 41 83 e1 ?? 47 8a 0c 08 44 30 0c 01 48 ff c0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}