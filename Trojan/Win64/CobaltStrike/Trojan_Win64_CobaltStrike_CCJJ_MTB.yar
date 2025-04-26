
rule Trojan_Win64_CobaltStrike_CCJJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCJJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 48 8d 45 d0 48 89 44 24 28 48 8d 05 a1 2c 00 00 48 89 44 24 20 ff 15 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}