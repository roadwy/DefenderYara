
rule Trojan_Win32_RelineStealer_VK_MTB{
	meta:
		description = "Trojan:Win32/RelineStealer.VK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {f0 3b 06 6c c7 84 24 ?? ?? ?? ?? 91 d5 b8 3c c7 84 24 ?? ?? ?? ?? ed cf 0e 06 c7 84 24 ?? ?? ?? ?? da 73 71 22 c7 84 24 ?? ?? ?? ?? 84 1f e8 75 c7 84 24 ?? ?? ?? ?? 17 64 50 28 } //10
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_80_2 = {43 6f 70 79 72 69 67 68 74 20 28 43 29 20 32 30 32 32 2c 20 70 6f 7a 6b 61 72 74 65 } //Copyright (C) 2022, pozkarte  1
	condition:
		((#a_02_0  & 1)*10+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}