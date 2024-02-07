
rule Trojan_Win32_RelineStealer_VK_MTB{
	meta:
		description = "Trojan:Win32/RelineStealer.VK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {f0 3b 06 6c c7 84 24 90 01 04 91 d5 b8 3c c7 84 24 90 01 04 ed cf 0e 06 c7 84 24 90 01 04 da 73 71 22 c7 84 24 90 01 04 84 1f e8 75 c7 84 24 90 01 04 17 64 50 28 90 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_80_2 = {43 6f 70 79 72 69 67 68 74 20 28 43 29 20 32 30 32 32 2c 20 70 6f 7a 6b 61 72 74 65 } //Copyright (C) 2022, pozkarte  00 00 
	condition:
		any of ($a_*)
 
}