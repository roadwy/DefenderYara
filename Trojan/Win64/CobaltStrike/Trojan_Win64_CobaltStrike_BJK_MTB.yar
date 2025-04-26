
rule Trojan_Win64_CobaltStrike_BJK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 8b ac 00 00 00 2b c1 48 63 4b 54 01 83 b0 00 00 00 0f b6 c2 0f b6 53 50 0f af d0 48 8b 83 c8 00 00 00 88 14 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}