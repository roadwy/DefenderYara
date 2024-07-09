
rule Trojan_Win32_CobaltStrike_CO_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.CO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d fc 83 c1 ?? 89 4d ?? 8b 55 ?? 3b 55 ?? 73 ?? 0f b6 45 ?? 8b 4d ?? 03 4d ?? 0f be 11 33 d0 8b 45 ?? 03 45 ?? 88 10 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}