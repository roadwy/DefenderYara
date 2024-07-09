
rule Trojan_Win32_Emotet_EX{
	meta:
		description = "Trojan:Win32/Emotet.EX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {85 ff 74 22 29 c9 49 23 0a 83 c2 04 83 c1 ee 31 d9 8d 49 ff 89 cb 89 4e 00 83 ef 04 83 ee fc b9 ?? ?? ?? ?? ff e1 } //2
		$a_02_1 = {09 c6 56 81 f9 ?? ?? 00 00 74 1d 8b 03 8d 5b 04 83 e8 ?? 31 f8 48 89 c7 89 46 00 83 e9 fc 83 c6 04 b8 ?? ?? ?? ?? ff e0 } //2
		$a_00_2 = {69 78 78 78 5f 72 6f 5f 65 5f 5f 4d 65 6d 6f 72 79 } //1 ixxx_ro_e__Memory
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_00_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Emotet_EX_2{
	meta:
		description = "Trojan:Win32/Emotet.EX,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 01 e8 08 04 00 00 83 c4 04 8b 0d 00 b2 41 00 89 0d ac b1 41 00 8b 15 0c b0 41 00 a1 c4 b1 41 00 8d 8c 10 68 2b 00 00 2b 4d f4 03 0d cc b1 41 00 89 0d cc b1 41 00 8b 15 cc b1 41 00 81 ea 68 2b 00 00 89 15 cc b1 41 00 a1 0c b0 41 00 03 45 f4 03 05 c8 b1 41 00 a3 c8 b1 41 00 8b 0d a8 b1 41 00 2b 0d ac b1 41 00 89 0d a8 b1 41 00 83 3d e8 b1 41 00 00 0f 85 54 ff ff ff } //1
		$a_01_1 = {55 8b ec 83 ec 08 8b 45 0c 89 45 fc c7 45 f8 01 00 00 00 8b 0d 38 b2 41 00 89 4d 08 8b 55 fc 83 c2 01 2b 55 f8 8b 45 08 03 10 8b 4d 08 89 11 8b e5 5d c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}