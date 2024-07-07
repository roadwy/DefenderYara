
rule Trojan_Win64_CobaltStrike_YEK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 94 24 40 03 00 00 0f b6 0c 11 8b c1 99 f7 bc 24 80 06 00 00 8b c2 03 44 24 20 8b 8c 24 d4 04 00 00 03 c1 89 44 24 20 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}