
rule Trojan_Win64_CobaltStrike_YK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 f9 e8 ?? ?? ?? ?? 48 8b 8d ?? ?? ?? ?? 42 30 04 31 49 ff c6 4c 39 f3 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}