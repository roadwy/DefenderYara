
rule Trojan_Win64_CobaltStrike_CCJH_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCJH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 41 83 f9 08 48 0f 45 d0 8a 04 0a 41 30 00 33 c0 41 83 f9 08 41 0f 45 c1 41 ff c2 49 ff c0 44 8d 48 01 48 8d 42 01 41 81 fa } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}