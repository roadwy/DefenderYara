
rule Trojan_Win32_Banload_MA_MTB{
	meta:
		description = "Trojan:Win32/Banload.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {a2 30 ba 4a 00 b8 69 98 49 00 a3 34 bb 4a 00 a1 c4 90 4a 00 bb 01 00 00 00 c6 44 24 0e 00 c6 44 24 0d 00 c7 44 24 10 01 00 00 00 89 44 24 14 3b c3 0f 8e } //01 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 31 37 36 2e 39 36 2e 31 33 38 2e 31 30 33 2f 6b 65 79 62 69 6e 64 65 72 } //01 00  http://176.96.138.103/keybinder
		$a_01_2 = {45 73 63 61 70 65 } //01 00  Escape
		$a_01_3 = {43 61 70 73 4c 6f 63 6b } //00 00  CapsLock
	condition:
		any of ($a_*)
 
}