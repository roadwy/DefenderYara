
rule Trojan_Win64_CobaltStrikePacker_AC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrikePacker.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 98 48 8b 8c 24 90 01 04 0f b6 04 01 8b 8c 24 90 01 04 33 c8 8b c1 48 63 8c 24 90 01 04 48 8b 94 24 90 01 04 88 04 0a 90 13 8b 84 24 90 01 04 83 c0 01 89 84 24 90 01 04 8b 84 24 90 01 04 39 84 24 90 01 04 0f 83 90 01 04 48 63 84 24 90 01 04 48 8b 8c 24 90 01 04 0f b6 04 01 89 84 24 90 01 04 8b 84 24 90 01 04 99 b9 90 01 04 f7 f9 8b c2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}