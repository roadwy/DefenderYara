
rule Trojan_Win64_CobaltStrike_PBE_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 8c 24 90 01 04 48 8b 84 24 90 01 04 44 0f b6 04 08 8b 84 24 90 01 04 99 b9 27 00 00 00 f7 f9 48 63 ca 48 8b 84 24 90 01 04 0f b6 04 08 41 8b d0 33 d0 48 63 8c 24 90 01 04 48 8b 84 24 90 01 04 88 14 08 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}