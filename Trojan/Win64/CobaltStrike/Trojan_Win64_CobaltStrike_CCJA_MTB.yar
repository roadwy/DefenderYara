
rule Trojan_Win64_CobaltStrike_CCJA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b ca f7 d2 c1 e9 18 33 c1 23 c2 41 ff c9 66 41 39 30 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}