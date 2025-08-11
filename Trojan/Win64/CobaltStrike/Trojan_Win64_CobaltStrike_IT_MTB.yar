
rule Trojan_Win64_CobaltStrike_IT_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.IT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 45 f8 48 8b 55 10 48 8b 45 f8 41 b8 0a 00 00 00 48 89 c1 48 8b 05 ?? ?? ?? ?? ff d0 48 89 45 f0 48 8b 55 f0 48 8b 45 f8 48 89 c1 48 8b 05 ?? ?? ?? ?? ff d0 48 89 45 e8 48 8b 55 f0 48 8b 45 f8 48 89 c1 48 8b 05 ?? ?? ?? ?? ff d0 48 8b 55 20 89 02 48 8b 45 e8 48 89 c1 48 8b 05 ?? ?? ?? ?? ff d0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}