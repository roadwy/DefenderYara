
rule Trojan_Win32_CobaltStrike_FST_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.FST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c1 8b 8e 88 00 00 00 01 46 40 8b 46 38 88 1c 01 ff 46 38 a1 ?? ?? ?? ?? 8b 48 08 a1 ?? ?? ?? ?? 48 03 c1 09 86 9c 00 00 00 8b 46 08 48 31 05 ?? ?? ?? ?? 8b 4e 60 8b 46 20 83 c1 fe 03 c1 31 86 94 00 00 00 b8 47 d2 13 00 8b 0d ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 01 41 54 b9 01 00 00 00 a1 ?? ?? ?? ?? 2b 48 08 2b 4e 78 01 4e 08 81 ff 20 1f 00 00 0f 8c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}