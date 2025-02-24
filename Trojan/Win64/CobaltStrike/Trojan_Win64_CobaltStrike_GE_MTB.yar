
rule Trojan_Win64_CobaltStrike_GE_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 44 01 da d8 62 26 a0 c2 85 80 ae e6 a6 bf 47 f5 30 93 f5 1b ee e0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}