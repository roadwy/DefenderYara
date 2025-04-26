
rule Trojan_Win32_CobaltStrike_CAM_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.CAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 31 41 04 a1 ?? ?? ?? ?? 8b 88 88 00 00 00 2b 88 dc 00 00 00 8b 86 c0 00 00 00 81 c1 42 77 04 00 03 86 9c 00 00 00 01 8e b8 00 00 00 83 f0 4a 0f af 86 fc 00 00 00 89 86 fc 00 00 00 a1 ?? ?? ?? ?? 3b 50 38 76 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}