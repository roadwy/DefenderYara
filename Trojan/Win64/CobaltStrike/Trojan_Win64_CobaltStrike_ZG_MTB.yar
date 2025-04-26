
rule Trojan_Win64_CobaltStrike_ZG_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 f7 e9 41 8b c9 41 ff c1 c1 fa 03 8b c2 c1 e8 1f 03 d0 6b c2 11 2b c8 48 63 c1 0f b6 4c 04 30 41 30 4a ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}