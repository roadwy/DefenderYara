
rule TrojanSpy_Win32_Pophot_A{
	meta:
		description = "TrojanSpy:Win32/Pophot.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {c6 03 43 c6 43 01 72 c6 43 02 65 c6 43 03 61 c6 43 04 74 c6 43 05 65 c6 43 06 44 c6 43 07 69 c6 43 08 72 c6 43 09 65 c6 43 0a 63 c6 43 0b 74 c6 43 0c 6f c6 43 0d 72 c6 43 0e 79 c6 43 0f 41 c6 43 10 00 53 8b 45 f8 50 e8 ?? ?? ?? ?? 8b d8 8d 45 e0 e8 ?? ?? ?? ?? 57 56 ff d3 83 f8 01 1b c0 40 88 45 ff 33 c0 5a 59 59 } //1
		$a_00_1 = {c6 03 46 c6 43 01 69 c6 43 02 6e c6 43 03 64 c6 43 04 57 c6 43 05 69 c6 43 06 6e c6 43 07 64 c6 43 08 6f c6 43 09 77 c6 43 0a 41 c6 43 0b 00 } //1
		$a_00_2 = {c6 03 47 c6 43 01 65 c6 43 02 74 c6 43 03 57 c6 43 04 69 c6 43 05 6e c6 43 06 64 c6 43 07 6f c6 43 08 77 c6 43 09 54 c6 43 0a 68 c6 43 0b 72 c6 43 0c 65 c6 43 0d 61 c6 43 0e 64 c6 43 0f 50 c6 43 10 72 c6 43 11 6f c6 43 12 63 c6 43 13 65 c6 43 14 73 c6 43 15 73 c6 43 16 49 c6 43 17 64 c6 43 18 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}