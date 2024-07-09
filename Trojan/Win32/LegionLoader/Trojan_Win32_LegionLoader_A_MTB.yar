
rule Trojan_Win32_LegionLoader_A_MTB{
	meta:
		description = "Trojan:Win32/LegionLoader.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 08 00 00 00 6b c8 00 ba 78 65 63 2e c7 44 0d e8 6d 73 69 65 89 54 0d ec c7 45 e4 eb 16 a3 12 b8 08 00 00 00 c1 e0 00 33 c9 c7 44 05 e8 65 78 65 00 89 4c 05 ec 8d 55 e8 52 8b 45 f8 50 ff 15 30 ?? 04 10 85 c0 74 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}