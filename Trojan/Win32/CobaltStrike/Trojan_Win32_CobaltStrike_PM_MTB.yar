
rule Trojan_Win32_CobaltStrike_PM_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.PM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 d8 0f b6 44 1e ?? 88 44 3e ?? 88 4c 1e ?? 02 c8 0f b6 c1 8b 4d ?? 8a 44 30 ?? 32 44 11 ?? 83 6d ?? ?? 88 42 ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}