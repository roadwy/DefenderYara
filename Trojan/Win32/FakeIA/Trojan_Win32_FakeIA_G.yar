
rule Trojan_Win32_FakeIA_G{
	meta:
		description = "Trojan:Win32/FakeIA.G,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {57 69 6e 64 6f 77 73 20 53 65 63 75 72 69 74 79 20 41 6c 65 72 74 } //01 00  Windows Security Alert
		$a_00_1 = {53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 20 41 6c 65 72 74 } //07 00  Security Center Alert
		$a_03_2 = {c6 03 48 c6 43 01 69 c6 43 02 67 c6 43 03 68 c6 43 04 00 8d 85 90 01 02 ff ff 8b d3 e8 90 01 04 8b 85 90 01 02 ff ff e8 90 01 04 50 53 6a 76 6a 7d 56 e8 90 00 } //03 00 
		$a_03_3 = {7e 25 bf 01 00 00 00 8d 45 f8 8b 55 fc 8a 54 3a ff 80 f2 ff e8 90 01 02 ff ff 8b 55 f8 8b c6 e8 90 01 02 ff ff 90 00 } //03 00 
		$a_03_4 = {84 c0 74 36 8b 15 90 01 04 83 ea 04 b8 90 01 04 b9 04 00 00 00 e8 90 01 04 68 90 01 04 6a 10 a1 90 01 04 83 c0 04 50 a1 90 01 04 83 e8 04 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}