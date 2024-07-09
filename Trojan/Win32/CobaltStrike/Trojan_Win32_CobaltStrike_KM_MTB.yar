
rule Trojan_Win32_CobaltStrike_KM_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 08 8d 55 ?? 8b 45 ?? 01 d0 0f b6 00 31 c1 89 ca 8d 8d ?? ?? ?? ?? 8b 45 ?? 01 c8 88 10 83 45 ?? ?? 83 45 ?? ?? 8b 45 ?? 3d ?? ?? ?? ?? 76 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}