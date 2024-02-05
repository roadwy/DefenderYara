
rule Trojan_Win32_Sirefef_B{
	meta:
		description = "Trojan:Win32/Sirefef.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 e1 ff 00 00 00 8a 04 31 03 d7 30 02 47 3b 7d 0c 7c c4 } //01 00 
		$a_03_1 = {c7 00 10 00 01 00 ff 76 04 6a fe ff 15 90 01 04 8b 46 04 90 01 02 b0 00 00 00 90 00 } //01 00 
		$a_03_2 = {33 db 8b d3 fe c3 8a 04 33 02 d0 8a 24 32 88 24 33 02 e0 88 04 32 0f b6 c4 8a 04 30 30 07 47 e2 e3 90 09 05 00 b9 90 00 } //01 00 
		$a_03_3 = {81 38 04 00 00 80 75 24 8b 40 0c 3b 05 90 01 04 75 19 8b 41 04 c7 80 b8 00 00 00 90 00 } //01 00 
		$a_03_4 = {03 c1 25 ff 00 00 00 8a 84 05 90 01 04 03 fe 30 07 46 3b f2 7c b2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Sirefef_B_2{
	meta:
		description = "Trojan:Win32/Sirefef.B,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 e1 ff 00 00 00 8a 04 31 03 d7 30 02 47 3b 7d 0c 7c c4 } //01 00 
		$a_03_1 = {c7 00 10 00 01 00 ff 76 04 6a fe ff 15 90 01 04 8b 46 04 90 01 02 b0 00 00 00 90 00 } //01 00 
		$a_03_2 = {33 db 8b d3 fe c3 8a 04 33 02 d0 8a 24 32 88 24 33 02 e0 88 04 32 0f b6 c4 8a 04 30 30 07 47 e2 e3 90 09 05 00 b9 90 00 } //01 00 
		$a_03_3 = {81 38 04 00 00 80 75 24 8b 40 0c 3b 05 90 01 04 75 19 8b 41 04 c7 80 b8 00 00 00 90 00 } //01 00 
		$a_03_4 = {03 c1 25 ff 00 00 00 8a 84 05 90 01 04 03 fe 30 07 46 3b f2 7c b2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}