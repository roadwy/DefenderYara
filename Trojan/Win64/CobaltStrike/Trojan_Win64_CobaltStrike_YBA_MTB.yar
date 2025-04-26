
rule Trojan_Win64_CobaltStrike_YBA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 01 d0 48 29 c1 48 89 ca 0f b6 84 15 ?? ?? ?? ?? 44 31 c8 41 88 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}