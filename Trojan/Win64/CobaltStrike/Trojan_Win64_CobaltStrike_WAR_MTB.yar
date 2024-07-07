
rule Trojan_Win64_CobaltStrike_WAR_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.WAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 f7 e8 c1 fa 04 8b c2 c1 e8 90 01 01 03 d0 41 8b c0 41 ff c0 8d 0c 92 c1 e1 90 01 01 2b c1 48 63 c8 48 8b 44 24 90 01 01 42 8a 8c 11 90 01 04 43 32 8c 11 90 01 04 41 88 0c 01 49 63 c0 49 ff c1 48 3b 44 24 90 01 01 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}