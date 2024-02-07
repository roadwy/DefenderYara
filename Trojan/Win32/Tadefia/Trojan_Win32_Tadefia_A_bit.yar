
rule Trojan_Win32_Tadefia_A_bit{
	meta:
		description = "Trojan:Win32/Tadefia.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {d3 e0 8b cf f7 d9 8b 90 01 02 d3 90 01 01 0b c2 89 90 01 02 8b 90 01 02 33 90 00 } //05 00 
		$a_01_1 = {54 68 69 73 20 66 69 6c 65 20 63 72 65 61 74 65 64 20 62 79 20 74 72 69 61 6c 20 76 65 72 73 69 6f 6e 20 6f 66 20 51 75 69 63 6b 20 42 61 74 63 68 20 46 69 6c 65 20 43 6f 6d 70 69 6c 65 72 } //01 00  This file created by trial version of Quick Batch File Compiler
		$a_03_2 = {66 6f 72 6d 61 74 20 90 01 01 3a 90 00 } //01 00 
		$a_01_3 = {72 64 20 2f 73 20 2f 71 20 63 3a 5c } //00 00  rd /s /q c:\
	condition:
		any of ($a_*)
 
}