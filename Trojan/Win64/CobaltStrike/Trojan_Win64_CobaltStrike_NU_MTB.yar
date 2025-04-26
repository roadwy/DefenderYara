
rule Trojan_Win64_CobaltStrike_NU_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.NU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 08 48 3b 44 24 20 0f 83 47 00 00 00 48 8b 44 24 18 48 89 04 24 48 8b 44 24 08 31 c9 89 ca 48 f7 74 24 10 48 8b 04 24 44 0f b6 04 10 48 8b 44 24 28 48 8b 4c 24 08 0f b6 14 08 44 31 c2 88 14 08 48 8b 44 24 08 48 83 c0 01 48 89 44 24 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}