
rule Trojan_Win32_CobaltStrike_KJ_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.KJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 83 f0 ?? 25 ?? ?? ?? ?? 21 f9 09 f2 89 55 ?? 09 c8 89 45 ?? 8b 4d ?? 8b 45 ?? 31 c8 88 45 ?? 8b 45 ?? 8a 4d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}