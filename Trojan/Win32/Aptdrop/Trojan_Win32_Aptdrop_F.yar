
rule Trojan_Win32_Aptdrop_F{
	meta:
		description = "Trojan:Win32/Aptdrop.F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {51 b9 40 9c 00 00 8b c5 05 01 01 01 01 51 8a c8 d3 c0 59 51 8a c8 d3 c0 59 05 01 01 01 00 05 01 01 01 01 8b e8 e2 df 59 8b dd ac 32 c3 aa e2 d0 } //01 00 
		$a_01_1 = {47 6f 6f 64 20 6e 69 67 68 74 20 66 6f 72 20 61 20 77 61 6c 6b } //00 00  Good night for a walk
	condition:
		any of ($a_*)
 
}