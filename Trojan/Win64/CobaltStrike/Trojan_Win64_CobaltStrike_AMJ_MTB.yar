
rule Trojan_Win64_CobaltStrike_AMJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AMJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 2a c1 41 32 c0 88 44 15 ?? ff c2 44 8b 75 ?? 41 3b d6 73 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}