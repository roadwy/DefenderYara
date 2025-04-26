
rule Trojan_Win32_RacoonStealer_AY_MTB{
	meta:
		description = "Trojan:Win32/RacoonStealer.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {45 08 5f 89 30 5e 89 58 04 5b c9 c2 04 00 90 0a 2b 00 2b 75 ?? 8d 45 ?? 89 3d ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 4d ?? 0f 85 ?? ?? ?? ?? 8b } //1
		$a_01_1 = {4c 6f 63 61 6c 41 6c 6c 6f 63 } //1 LocalAlloc
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}