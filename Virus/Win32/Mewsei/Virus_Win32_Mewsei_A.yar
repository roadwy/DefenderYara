
rule Virus_Win32_Mewsei_A{
	meta:
		description = "Virus:Win32/Mewsei.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {69 f6 fd 43 03 00 81 c6 c3 9e 26 00 8b c6 c1 e8 10 25 ff 7f 00 00 33 d2 bb ff 00 00 00 f7 f3 8b 45 08 41 fe c2 88 54 0f ff 3b c8 72 d3 } //1
		$a_03_1 = {f6 d9 30 0c ?? 42 ?? 3b ?? 72 eb 85 c0 74 09 50 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}