
rule Trojan_Win32_NSISInject_DN_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.DN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 f9 c8 12 00 00 74 ?? 04 69 04 27 fe c8 2c 46 34 a4 2c 55 2c f4 fe c0 fe c8 fe c0 2c c9 fe c0 fe c0 2c bf 88 84 0d ?? ?? ?? ?? 83 c1 01 eb 90 09 07 00 8a 84 0d } //1
		$a_03_1 = {81 f9 e7 13 00 00 74 ?? fe c0 04 19 2c 5a 34 8b 04 30 fe c8 04 ef fe c8 04 c1 fe c8 fe c8 fe c8 34 72 2c 8b fe c8 fe c8 04 b9 04 76 88 84 0d ?? ?? ?? ?? 83 c1 01 eb 90 09 07 00 8a 84 0d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}