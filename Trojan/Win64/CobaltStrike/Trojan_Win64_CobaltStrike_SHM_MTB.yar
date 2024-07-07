
rule Trojan_Win64_CobaltStrike_SHM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SHM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 5c 04 21 89 da f6 d2 80 e2 15 80 e3 ea 08 d3 88 5c 04 21 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}