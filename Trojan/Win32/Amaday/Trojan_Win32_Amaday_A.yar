
rule Trojan_Win32_Amaday_A{
	meta:
		description = "Trojan:Win32/Amaday.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {c6 05 1a d4 42 00 72 c6 05 ?? ?? ?? 00 73 c6 05 ?? ?? ?? 00 74 c6 05 ?? ?? ?? 00 57 c6 05 ?? ?? ?? 00 00 c6 05 ?? ?? ?? 00 65 c6 05 ?? ?? ?? 00 33 c6 05 ?? ?? ?? 00 32 c6 05 ?? ?? ?? 00 46 c6 05 ?? ?? ?? 00 69 c6 05 ?? ?? ?? 00 4d c6 05 ?? ?? ?? 00 6f c6 05 ?? ?? ?? 00 64 c6 05 ?? ?? ?? 00 75 c6 05 ?? ?? ?? 00 6c } //1
		$a_03_1 = {3b 5f b5 5c c7 44 24 [0-04] ae 44 07 52 c7 44 24 [0-04] d2 5f d2 66 c7 84 24 [0-06] ee 3e c7 44 24 [0-04] eb b8 b5 5f c7 84 24 [0-04] 71 25 48 57 c7 44 24 [0-04] 4d 28 48 7e c7 84 24 [0-04] 82 18 a9 02 c7 84 24 [0-04] 83 c8 92 38 c7 84 24 [0-04] 6f 4d 66 78 c7 44 24 [0-04] 1b f9 f5 21 c7 44 24 [0-04] d3 e8 9f 34 c7 44 24 [0-04] 46 18 19 7b c7 84 24 [0-04] e6 54 c0 04 c7 44 24 [0-04] 87 b0 41 44 c7 44 24 [0-04] 63 9f a1 51 c7 44 24 [0-04] 34 bc cf 04 c7 84 24 [0-04] 2c 7f 16 7f c7 44 24 [0-04] 0b e2 81 33 c7 44 24 [0-04] a7 1b 2b 5e c7 44 24 [0-04] ac ff b1 48 c7 44 24 [0-04] 13 52 10 19 c7 84 24 [0-04] f1 9b 0d 21 c7 44 24 [0-04] 03 bc a3 59 c7 84 24 [0-04] bb 81 20 22 c7 44 24 [0-04] 25 02 22 16 } //1
		$a_03_2 = {3b 5f b5 5c c7 84 24 [0-04] ae 44 07 52 c7 84 24 [0-04] d2 5f d2 66 c7 44 24 [0-06] ee 3e c7 44 24 [0-04] eb b8 b5 5f c7 84 24 [0-04] 71 25 48 57 c7 44 24 [0-04] 4d 28 48 7e c7 44 24 [0-04] 82 18 a9 02 c7 44 24 [0-04] 83 c8 92 38 c7 84 24 [0-04] 6f 4d 66 78 c7 84 24 [0-04] 1b f9 f5 21 c7 84 24 [0-04] d3 e8 9f 34 c7 84 24 [0-04] 46 18 19 7b c7 84 24 [0-04] e6 54 c0 04 c7 84 24 [0-04] 87 b0 41 44 c7 44 24 [0-04] 63 9f a1 51 c7 84 24 [0-04] 34 bc cf 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}