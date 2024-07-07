
rule Trojan_Win64_CobaltStrike_RDG_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.RDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 4c 24 24 0f b6 04 08 33 44 24 34 88 c2 48 8b 44 24 28 48 63 4c 24 24 88 14 08 8b 44 24 24 83 c0 01 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}