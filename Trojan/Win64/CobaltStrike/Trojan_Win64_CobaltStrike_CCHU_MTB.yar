
rule Trojan_Win64_CobaltStrike_CCHU_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {bd 6c 04 00 00 8b 44 24 70 31 e8 b9 ?? ?? ?? ?? 44 89 f2 44 89 e3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}