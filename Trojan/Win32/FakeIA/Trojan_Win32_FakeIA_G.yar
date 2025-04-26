
rule Trojan_Win32_FakeIA_G{
	meta:
		description = "Trojan:Win32/FakeIA.G,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 05 00 00 "
		
	strings :
		$a_00_0 = {57 69 6e 64 6f 77 73 20 53 65 63 75 72 69 74 79 20 41 6c 65 72 74 } //1 Windows Security Alert
		$a_00_1 = {53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 20 41 6c 65 72 74 } //1 Security Center Alert
		$a_03_2 = {c6 03 48 c6 43 01 69 c6 43 02 67 c6 43 03 68 c6 43 04 00 8d 85 ?? ?? ff ff 8b d3 e8 ?? ?? ?? ?? 8b 85 ?? ?? ff ff e8 ?? ?? ?? ?? 50 53 6a 76 6a 7d 56 e8 } //7
		$a_03_3 = {7e 25 bf 01 00 00 00 8d 45 f8 8b 55 fc 8a 54 3a ff 80 f2 ff e8 ?? ?? ff ff 8b 55 f8 8b c6 e8 ?? ?? ff ff } //3
		$a_03_4 = {84 c0 74 36 8b 15 ?? ?? ?? ?? 83 ea 04 b8 ?? ?? ?? ?? b9 04 00 00 00 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 10 a1 ?? ?? ?? ?? 83 c0 04 50 a1 ?? ?? ?? ?? 83 e8 04 50 e8 } //3
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*7+(#a_03_3  & 1)*3+(#a_03_4  & 1)*3) >=6
 
}