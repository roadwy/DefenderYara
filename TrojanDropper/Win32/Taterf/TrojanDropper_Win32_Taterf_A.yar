
rule TrojanDropper_Win32_Taterf_A{
	meta:
		description = "TrojanDropper:Win32/Taterf.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {66 8b 10 83 c0 02 66 81 f2 90 01 02 81 ea 90 01 04 41 66 89 50 fe 8b 96 90 01 02 00 00 d1 ea 3b ca 72 de 90 00 } //01 00 
		$a_03_1 = {8a 51 02 83 fa 68 75 90 01 09 8a 48 03 83 f9 13 75 08 6a 00 ff 15 90 00 } //01 00 
		$a_00_2 = {6e 6f 64 33 32 66 75 63 6b 00 } //00 00  潮㍤昲捵k
	condition:
		any of ($a_*)
 
}