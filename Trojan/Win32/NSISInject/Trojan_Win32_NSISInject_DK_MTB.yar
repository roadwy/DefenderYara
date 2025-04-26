
rule Trojan_Win32_NSISInject_DK_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 04 68 00 30 00 00 68 00 a3 e1 11 6a 00 ff 15 } //5
		$a_03_1 = {d1 f8 0f b6 0d ?? ?? ?? ?? c1 e1 07 0b c1 a2 ?? ?? ?? ?? 8b 15 90 09 20 00 88 0d ?? ?? ?? ?? 0f b6 15 ?? ?? ?? ?? 33 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 0f b6 05 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*1) >=6
 
}
rule Trojan_Win32_NSISInject_DK_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {fe c8 fe c0 fe c8 fe c8 fe c8 2c 77 fe c0 2c 7e 2c 51 2c 83 fe c8 fe c0 04 f6 fe c0 34 76 2c 48 fe c8 04 d3 2c cf 88 81 ?? ?? ?? ?? 83 c1 01 eb } //1
		$a_03_1 = {34 1c 34 ad fe c0 fe c8 04 48 fe c0 fe c0 34 6f 34 e2 2c b4 34 72 04 0c fe c0 2c dc fe c8 fe c0 2c 06 fe c0 04 93 88 81 ?? ?? ?? ?? 83 c1 01 eb } //1
		$a_03_2 = {04 2d 34 2a 2c 94 fe c8 2c 0f fe c0 fe c8 04 5a fe c0 fe c0 34 6b 2c 05 fe c0 2c b5 34 35 04 e4 34 f6 34 a9 fe c8 88 81 ?? ?? ?? ?? 83 c1 01 eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}