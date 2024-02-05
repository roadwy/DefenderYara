
rule Trojan_Win32_Foosace_E_dha{
	meta:
		description = "Trojan:Win32/Foosace.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 04 00 "
		
	strings :
		$a_00_0 = {8b 45 08 6a 07 03 c7 33 d2 89 45 e0 8d 47 01 5b f7 f3 8a d9 6a 07 02 5d 0f 8a 04 32 33 d2 f6 eb 8a d8 8b c7 5f f7 f7 8b 7d f8 6a 07 8a 44 37 fe 02 45 fc 02 1c 32 b2 03 f6 ea 88 5d 13 8a d8 02 d9 8d 47 ff 33 d2 59 f7 f1 8a 4d 13 8b 45 e0 c0 e3 06 02 1c 32 32 cb 30 08 8b 4d 14 41 47 3b 4d e4 89 4d 14 89 7d f8 72 97 } //02 00 
		$a_01_1 = {49 6e 69 74 31 } //02 00 
		$a_80_2 = {37 30 2e 38 35 2e 32 32 31 2e 31 30 } //70.85.221.10  02 00 
		$a_80_3 = {7e 78 68 2f 63 68 2e 63 67 69 } //~xh/ch.cgi  00 00 
		$a_00_4 = {78 18 01 00 03 00 } //03 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Foosace_E_dha_2{
	meta:
		description = "Trojan:Win32/Foosace.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 6c 6c 2e 64 6c 6c 90 02 02 53 74 61 72 74 90 00 } //02 00 
		$a_01_1 = {59 5a 5a 41 4d 75 74 65 78 00 } //01 00 
		$a_01_2 = {49 6e 69 74 31 00 } //01 00 
		$a_01_3 = {f7 f7 8b 45 14 c1 eb 07 32 1c 02 8d 46 01 33 d2 f7 f7 8a 45 0f 02 c1 8b 4d 14 8a 0c 0a } //01 00 
		$a_01_4 = {8a 54 37 fe 03 d3 03 d1 d3 ea 32 c2 8d 56 ff 83 e2 07 8a 1c 3a 8a 14 2e 32 c3 32 d0 41 88 14 2e 46 83 fe 0a 7c bb } //01 00 
		$a_00_5 = {f7 f7 2b 4d ec 8b 45 e0 f7 d9 1b c9 f7 d1 23 ca 33 d2 f7 f6 89 4d fc 3b ca 89 55 e0 73 7a } //01 00 
		$a_00_6 = {03 c1 03 45 14 d3 e8 8d 4e ff 83 e1 07 32 d0 32 14 39 8b 45 f8 30 14 30 8b 75 f4 8d 56 fe 83 fa 08 72 b7 } //01 00 
		$a_00_7 = {8a c3 03 db 03 db 03 db 8b fe 2b fb 89 7d e8 bf 01 00 00 00 2b fb 89 7d ec 02 c0 bf 03 00 00 00 2b fb 02 c0 89 7d 0c 02 c0 bf 02 00 00 00 2b fb 88 45 13 8d 04 0b 89 7d 14 8b 7d 0c 8a 5d 13 02 d9 8b 4d 14 03 c8 03 f8 } //00 00 
		$a_00_8 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}