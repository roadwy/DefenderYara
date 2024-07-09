
rule Trojan_Win64_CobaltStrike_YBE_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 d0 48 c1 e8 ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 01 c0 48 89 ce 48 29 c6 0f b6 84 34 60 06 00 00 48 8d 15 ?? ?? ?? ?? 32 04 0a 48 8b 94 24 ?? ?? ?? ?? 88 04 0a 48 83 c1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}