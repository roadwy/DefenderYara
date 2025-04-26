
rule Trojan_Win32_NSISInject_DO_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.DO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 08 00 00 "
		
	strings :
		$a_03_0 = {81 f9 b5 14 00 00 74 ?? fe c0 fe c8 fe c0 fe c8 04 4c fe c8 04 46 fe c0 fe c8 fe c0 34 97 2c ae fe c0 fe c0 04 2d 2c f1 34 f2 fe c8 88 84 0d ?? ?? ?? ?? 83 c1 01 eb } //1
		$a_03_1 = {81 f9 d2 12 00 00 74 ?? fe c8 04 86 fe c0 fe c8 fe c8 fe c8 fe c0 04 76 fe c8 fe c0 34 ab 88 84 0d ?? ?? ?? ?? 83 c1 01 eb } //1
		$a_03_2 = {81 f9 01 13 00 00 74 ?? 2c a2 34 e5 fe c8 fe c0 fe c0 fe c0 fe c8 fe c8 fe c0 fe c0 2c 5e fe c8 34 3c 04 de fe c0 04 6c 34 5b 34 f5 88 84 0d ?? ?? ?? ?? 83 c1 01 eb } //1
		$a_03_3 = {81 f9 40 14 00 00 74 ?? fe c8 fe c8 04 43 04 e5 fe c8 2c 10 fe c8 34 41 fe c0 34 9b 2c 68 88 84 0d ?? ?? ?? ?? 83 c1 01 eb } //1
		$a_03_4 = {81 f9 7d 14 00 00 74 ?? 2c 4e fe c0 2c d5 fe c0 fe c0 fe c8 04 1e fe c0 fe c8 34 f2 2c 6a fe c0 04 02 2c 7e 04 f5 fe c0 34 28 fe c8 88 84 0d ?? ?? ?? ?? 83 c1 01 eb } //1
		$a_03_5 = {81 f9 b2 12 00 00 74 ?? 04 38 fe c0 04 8a fe c8 2c fe fe c8 34 61 34 f7 2c e9 34 37 34 45 2c 4f fe c8 fe c8 fe c8 88 84 0d ?? ?? ?? ?? 83 c1 01 eb } //1
		$a_03_6 = {81 f9 e8 12 00 00 74 ?? 04 10 34 e3 34 f5 04 14 04 05 2c df 34 2f fe c0 fe c0 fe c0 fe c8 88 84 0d ?? ?? ?? ?? 83 c1 01 eb } //1
		$a_03_7 = {81 f9 26 15 00 00 74 ?? 34 26 fe c8 04 f8 2c de 2c 1e 2c 06 34 d2 04 a6 04 7a fe c0 fe c0 fe c8 fe c0 fe c0 88 84 0d ?? ?? ?? ?? 83 c1 01 eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1+(#a_03_7  & 1)*1) >=1
 
}