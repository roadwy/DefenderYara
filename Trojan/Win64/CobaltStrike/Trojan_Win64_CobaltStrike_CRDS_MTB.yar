
rule Trojan_Win64_CobaltStrike_CRDS_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CRDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c9 ba e0 93 04 00 41 b8 00 10 00 00 44 8d 49 40 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}