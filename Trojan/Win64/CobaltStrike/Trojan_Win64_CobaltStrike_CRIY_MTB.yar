
rule Trojan_Win64_CobaltStrike_CRIY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CRIY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c2 83 e2 90 01 01 41 8a 14 14 32 54 05 00 88 14 03 48 ff c0 39 c6 7f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}