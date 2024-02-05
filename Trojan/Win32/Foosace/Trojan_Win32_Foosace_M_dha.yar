
rule Trojan_Win32_Foosace_M_dha{
	meta:
		description = "Trojan:Win32/Foosace.M!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 45 0c 59 85 db 7e 2c 57 8b 7d 08 2b fe 8d 0c 30 c7 45 90 01 04 90 01 01 33 d2 f7 75 90 01 01 8a 82 90 01 02 00 10 32 04 0f 88 01 8b 45 0c 40 89 45 0c 3b c3 7c db 90 00 } //01 00 
		$a_03_1 = {33 f6 8b d0 59 85 db 7e 1f 57 8b 7d 08 2b fa 8b c6 8d 0c 16 83 e0 0f 8a 80 90 01 02 00 10 32 04 0f 46 88 01 3b f3 7c e8 5f 5e 90 00 } //01 00 
		$a_01_2 = {4d 4e 4f 45 50 00 32 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}