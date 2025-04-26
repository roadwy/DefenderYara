
rule Trojan_Win64_CobaltStrike_CCJI_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCJI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 31 c9 45 31 c0 31 d2 48 89 44 24 28 48 8b 4c 24 48 48 89 74 24 20 ff 15 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}