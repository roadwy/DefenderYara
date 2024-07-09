
rule Trojan_Win32_CobaltStrike_HO_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.HO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 01 89 45 ?? 81 7d ?? ?? ?? ?? ?? 73 ?? 8b 45 ?? 03 45 ?? 0f b6 08 8b 55 ?? 03 55 ?? 0f b6 02 33 c1 8b 4d ?? 03 4d ?? 88 01 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}