
rule Trojan_Win64_CobaltStrike_GF_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 81 b0 00 00 00 8b 05 ?? ?? ?? ?? 01 43 30 48 8b 05 ?? ?? ?? ?? 8b 88 88 00 00 00 2b 48 18 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}