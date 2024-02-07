
rule Trojan_Win32_Vundo_gen_BX{
	meta:
		description = "Trojan:Win32/Vundo.gen!BX,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 14 88 8b 02 8b f8 33 7d 90 01 01 33 7d 90 01 01 89 45 90 01 01 89 3a 8b 45 90 01 01 8d 50 ff c1 ea 02 41 42 90 00 } //01 00 
		$a_03_1 = {6a 07 99 59 f7 f9 85 d2 74 24 8b 44 24 90 01 01 85 c0 75 05 b8 90 00 } //01 00 
		$a_01_2 = {78 32 5f 61 6c 69 76 65 5f 6d 75 74 65 78 } //01 00  x2_alive_mutex
		$a_01_3 = {70 72 6f 74 65 63 74 2e 64 6c 6c 00 69 6e 73 74 } //00 00 
	condition:
		any of ($a_*)
 
}