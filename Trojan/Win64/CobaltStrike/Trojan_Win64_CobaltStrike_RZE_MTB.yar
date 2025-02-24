
rule Trojan_Win64_CobaltStrike_RZE_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.RZE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 f7 e9 d1 fa 8b c2 c1 e8 1f 03 d0 41 8b c1 41 ff c1 8d 0c 52 c1 e1 ?? 2b c1 48 63 c8 42 0f b6 04 11 41 30 00 49 ff c0 49 8b c0 48 2b c6 48 3b c5 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}