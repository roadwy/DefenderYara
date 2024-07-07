
rule Trojan_Win64_CobaltStrike_AMBG_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AMBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 4c 24 90 02 01 48 89 d9 48 89 c3 48 8d 44 24 90 02 02 e8 90 02 04 48 8b 15 90 02 04 48 89 d9 48 89 c3 48 89 d0 90 02 02 e8 90 02 04 48 8b 4c 24 90 02 01 48 ff c1 48 39 0d 90 02 04 7f 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}