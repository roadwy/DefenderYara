
rule Virus_Win32_Mewsei_A{
	meta:
		description = "Virus:Win32/Mewsei.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 f6 fd 43 03 00 81 c6 c3 9e 26 00 8b c6 c1 e8 10 25 ff 7f 00 00 33 d2 bb ff 00 00 00 f7 f3 8b 45 08 41 fe c2 88 54 0f ff 3b c8 72 d3 } //01 00 
		$a_03_1 = {f6 d9 30 0c 90 01 01 42 90 01 01 3b 90 01 01 72 eb 85 c0 74 09 50 e8 90 00 } //00 00 
		$a_00_2 = {80 } //10 00 
	condition:
		any of ($a_*)
 
}