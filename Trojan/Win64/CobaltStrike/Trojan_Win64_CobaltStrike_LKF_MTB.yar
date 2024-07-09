
rule Trojan_Win64_CobaltStrike_LKF_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 8c 24 d8 00 00 00 0f b6 04 01 8b 4c 24 7c 33 c8 8b c1 48 63 4c 24 60 48 8b 54 24 70 88 04 0a e9 ?? ?? ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}