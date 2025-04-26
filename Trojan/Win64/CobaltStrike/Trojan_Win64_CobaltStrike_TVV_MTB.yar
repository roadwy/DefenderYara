
rule Trojan_Win64_CobaltStrike_TVV_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.TVV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 31 c2 88 14 0b 48 ff c1 48 89 d8 48 89 fa 48 39 ca 7e 34 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}