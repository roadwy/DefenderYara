
rule Trojan_Win64_CobaltStrike_DA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 01 d0 44 0f b6 08 48 8b 8d 90 01 04 48 89 c8 48 c1 e8 02 48 ba 90 01 08 48 f7 e2 48 89 d0 48 d1 e8 48 89 c2 48 8d 04 95 00 00 00 00 48 89 c2 48 8d 04 d5 00 00 00 00 90 00 } //1
		$a_03_1 = {48 29 d0 48 29 c1 48 89 c8 0f b6 84 05 90 01 04 44 31 c8 41 88 00 48 83 85 90 01 05 48 8b 85 90 01 04 48 39 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}