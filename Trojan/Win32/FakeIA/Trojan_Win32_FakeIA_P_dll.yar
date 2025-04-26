
rule Trojan_Win32_FakeIA_P_dll{
	meta:
		description = "Trojan:Win32/FakeIA.P!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_02_0 = {41 50 50 44 41 54 41 5c [0-0a] 2e 67 69 66 } //1
		$a_00_1 = {ff ff ff ff 13 00 00 00 ac b7 aa ab bb b0 a8 b1 df d2 8d df d2 99 df d2 8b df cf 00 } //1
		$a_03_2 = {8b 10 c6 02 ?? 8b 10 c6 42 01 ?? 8b 10 c6 42 02 [0-60] 8b 10 c6 42 ?? 00 8b 08 33 d2 33 c0 e8 ?? ?? ff ff 8b d8 e8 ?? ?? ff ff 85 c0 75 17 54 6a 00 6a 00 68 58 c3 40 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 5a 5b c3 } //1
		$a_03_3 = {8a 54 3a ff (80 f2|32 55) ?? e8 ?? ?? ?? ?? 8b 55 ?? 8b c6 e8 ?? ?? ?? ?? 47 4b 75 e0 } //1
		$a_03_4 = {83 fb 05 72 ?? 8b cb 8b d5 8b c7 e8 ?? ?? ?? ?? 8b c7 8b d0 03 d3 c6 02 e9 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}