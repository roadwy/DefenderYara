
rule Trojan_Win32_PSWStealer_VM_MTB{
	meta:
		description = "Trojan:Win32/PSWStealer.VM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {43 6f 70 79 72 69 67 68 74 20 28 43 29 20 32 30 32 32 2c 20 70 6f 7a 6b 61 72 74 65 } //Copyright (C) 2022, pozkarte  1
		$a_01_1 = {2e 70 64 62 } //1 .pdb
		$a_80_2 = {32 39 2e 34 37 2e 37 35 2e 32 33 } //29.47.75.23  1
		$a_80_3 = {32 32 2e 38 32 2e 37 34 2e 37 33 } //22.82.74.73  1
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_80_5 = {59 75 68 6f 76 6f 79 75 79 61 6d 6f 76 75 70 65 } //Yuhovoyuyamovupe  1
	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_01_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}