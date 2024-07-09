
rule Trojan_Win32_RelineStealer_FM_MTB{
	meta:
		description = "Trojan:Win32/RelineStealer.FM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_02_0 = {81 c1 96 00 00 00 89 8d ?? ?? ?? ?? 8b 55 08 81 c2 c2 00 00 00 89 95 ?? ?? ?? ?? 8b 45 08 83 c0 01 89 85 ?? ?? ?? ?? 8b 4d 08 83 c1 27 89 8d 84 fe ff ff 8b 55 08 81 c2 c6 00 00 00 89 95 ?? ?? ?? ?? 8b 45 08 83 c0 49 } //10
		$a_02_1 = {89 45 b0 8b 4d dc 0f af 8d ?? ?? ?? ?? 89 4d ec 8b 95 ?? ?? ?? ?? 0f af 95 ?? ?? ?? ?? 89 55 a0 8b 85 f0 fe ff ff 3b 45 88 7f 0c } //10
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_01_2  & 1)*1) >=21
 
}