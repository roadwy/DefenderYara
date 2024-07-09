
rule Trojan_Win64_CobaltStrike_CN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 83 c0 01 0f b7 04 01 41 89 d1 41 c1 c9 ?? 44 01 c8 31 c2 44 89 c0 80 3c 01 ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}