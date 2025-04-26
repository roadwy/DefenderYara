
rule Trojan_Win32_Rlsloup_B{
	meta:
		description = "Trojan:Win32/Rlsloup.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 75 70 6c 6f 61 64 73 2f 64 64 75 6d 70 00 } //1
		$a_00_1 = {50 55 54 00 5c 4d 69 6e 69 64 75 6d 70 5c 00 } //1
		$a_03_2 = {ff d5 85 c0 0f 84 ?? 00 00 00 8b 4c 24 20 8d 51 02 b8 ab aa aa aa f7 e2 8b f2 d1 ee 03 f6 03 f6 51 8b c6 e8 ?? ?? ff ff 83 c4 04 8d 44 24 24 50 56 68 ?? ?? ?? ?? 57 ff d3 } //1
		$a_03_3 = {c7 44 24 38 28 00 00 00 ff 15 ?? ?? ?? ?? 8b d0 83 c2 02 b8 ab aa aa aa f7 e2 53 6a 08 d1 ea 53 8d 44 24 3c 03 d2 50 03 d2 57 89 54 24 60 ff 15 ?? ?? ?? ?? 85 c0 0f 84 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}