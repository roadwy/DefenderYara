
rule Trojan_Win32_CobatStrike_NBL_MTB{
	meta:
		description = "Trojan:Win32/CobatStrike.NBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 c1 e8 05 89 45 fc 8b 45 f0 01 45 fc 8b 45 f8 8b fb c1 e7 04 03 7d ec 03 c3 33 f8 81 3d ?? ?? ?? ?? ?? ?? 00 00 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 75 0a 6a 00 6a 00 ff 15 2c 30 43 00 31 7d fc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}