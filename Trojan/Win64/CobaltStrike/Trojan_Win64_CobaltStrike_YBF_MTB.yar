
rule Trojan_Win64_CobaltStrike_YBF_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8d 04 52 48 c1 e0 03 48 29 d0 4c 89 c6 48 29 c6 0f b6 84 34 60 06 00 00 48 8d 15 90 01 04 42 32 04 02 48 8b 94 24 88 06 00 00 42 88 04 02 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}