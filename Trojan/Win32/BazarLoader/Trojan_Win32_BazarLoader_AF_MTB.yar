
rule Trojan_Win32_BazarLoader_AF_MTB{
	meta:
		description = "Trojan:Win32/BazarLoader.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {8a 0b 03 c2 03 f8 8b c6 c1 e0 10 0f af d7 40 0f af c6 03 55 f8 03 c2 8b 55 fc 42 89 45 f8 } //10
		$a_02_1 = {81 ec 58 07 00 00 a1 ?? ?? ?? ?? 33 c5 89 45 ec 56 57 50 8d 45 f4 64 a3 00 00 00 00 8b 73 10 8d 85 08 f9 ff ff } //10
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}