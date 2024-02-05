
rule Trojan_Win32_Vundo_gen_AP{
	meta:
		description = "Trojan:Win32/Vundo.gen!AP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {74 17 33 d2 8b 7d 10 0f bf c2 8d 04 81 31 38 42 66 83 fa 04 72 ee 8b 7d f8 53 8d 45 fc 50 6a 10 } //01 00 
		$a_03_1 = {2b f1 3b d0 72 02 33 d2 8a 1c 0e 32 9a 90 01 04 88 19 41 42 4f 75 ea 90 00 } //01 00 
		$a_03_2 = {72 2d 6a 14 59 8d 50 ec 3b c8 1b c0 23 c2 50 8b d7 33 c0 e8 90 01 04 35 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}