
rule Trojan_Win32_Toshliph_A{
	meta:
		description = "Trojan:Win32/Toshliph.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b f8 8b 47 3c 03 c7 89 45 ?? 8b 70 50 [0-50] 6a 40 68 00 30 00 00 50 53 8d 45 ?? 50 ff 75 ?? 89 5d 90 1b 02 8b f3 ff 15 ?? ?? ?? ?? 85 c0 75 ?? 8b 4d 90 1b 00 8b 45 90 1b 02 ff b1 a4 00 00 00 2b c7 50 8b 81 a0 00 00 00 } //1
		$a_01_1 = {8a 02 3c 2b 75 0b 66 c7 01 25 32 c6 41 02 42 eb 1c 3c 2f 75 0b 66 c7 01 25 32 c6 41 02 46 eb 0d 3c 3d 75 0e 66 c7 01 25 33 c6 41 02 44 83 c1 03 eb 03 88 01 } //1
		$a_03_2 = {6a 0f 6a 05 e8 ?? ?? ?? ?? 8b f0 8d 45 d0 56 50 e8 ?? ?? ?? ?? c7 44 35 d0 2e 70 68 70 c6 44 35 d4 3f 83 c6 05 8d 04 3e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}