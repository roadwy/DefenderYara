
rule Trojan_Win64_CobaltStrike_BY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c2 89 d0 c1 e0 90 01 01 01 d0 01 c0 29 c1 89 ca 48 63 c2 48 90 01 06 0f b6 14 10 8b 85 90 01 04 48 63 c8 48 90 01 06 48 01 c8 44 31 c2 88 10 83 85 90 01 05 8b 45 90 01 01 39 85 90 01 04 7c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}