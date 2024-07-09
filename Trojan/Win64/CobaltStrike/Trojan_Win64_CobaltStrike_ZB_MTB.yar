
rule Trojan_Win64_CobaltStrike_ZB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {43 30 14 08 48 8b ca 48 8b c2 48 c1 e9 38 48 83 c9 01 48 c1 e0 08 48 8b d1 49 ff c0 48 33 d0 49 83 f8 ?? 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}