
rule Trojan_Win32_CobaltStrike_BH_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 4c 24 ?? e8 ?? ?? ?? ?? 8b 4c 24 ?? 33 08 8b c1 89 44 24 ?? eb 8c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}