
rule Trojan_Win32_Winnti_dha{
	meta:
		description = "Trojan:Win32/Winnti!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 6e 73 74 61 6c 6c 00 54 73 65 74 00 } //1
		$a_00_1 = {33 c0 66 8b 02 8b e8 81 e5 00 f0 ff ff 81 fd 00 30 00 00 75 0d 8b 6c 24 18 25 ff 0f 00 00 03 c7 01 28 8b 41 04 46 83 e8 08 83 c2 02 d1 e8 3b f0 72 } //1
		$a_00_2 = {8b 07 8b c8 8b d0 c1 e9 1d c1 ea 1e 8b f0 83 e1 01 83 e2 01 c1 ee 1f a9 00 00 00 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}