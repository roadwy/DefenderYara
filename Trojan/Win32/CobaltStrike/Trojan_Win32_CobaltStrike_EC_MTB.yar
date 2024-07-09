
rule Trojan_Win32_CobaltStrike_EC_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a c6 84 24 ?? ?? ?? ?? c1 c6 84 24 ?? ?? ?? ?? 57 c6 84 24 ?? ?? ?? ?? 52 c6 84 24 ?? ?? ?? ?? f7 c7 44 24 ?? 50 10 03 00 8b 44 24 ?? 41 b9 04 00 00 00 41 b8 00 30 00 00 8b d0 33 c9 } //6
	condition:
		((#a_03_0  & 1)*6) >=6
 
}