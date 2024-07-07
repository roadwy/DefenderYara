
rule Trojan_Win64_CobaltStrike_RDH_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.RDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 8b c0 41 8b c8 2b c2 41 ff c0 d1 e8 03 c2 c1 e8 02 6b c0 07 2b c8 48 63 c1 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}