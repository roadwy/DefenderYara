
rule Trojan_Win32_CobaltStrike_CBM_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.CBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 86 00 01 00 00 35 5a 35 0d 00 0f af 81 00 01 00 00 89 81 00 01 00 00 8b 46 2c 01 86 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 88 f0 00 00 00 8b 46 58 40 03 c1 0f af 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 05 84 1f ed ff 01 86 98 00 00 00 81 fd b8 b8 01 00 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}