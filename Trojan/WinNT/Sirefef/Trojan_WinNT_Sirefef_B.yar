
rule Trojan_WinNT_Sirefef_B{
	meta:
		description = "Trojan:WinNT/Sirefef.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {03 ce d1 f9 8b 34 88 03 75 08 89 4d fc 6a 0f bf } //01 00 
		$a_03_1 = {33 db 8b d3 fe c3 8a 04 33 02 d0 8a 24 32 88 24 33 02 e0 88 04 32 0f b6 c4 8a 04 30 30 07 47 e2 e3 90 09 05 00 b9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_WinNT_Sirefef_B_2{
	meta:
		description = "Trojan:WinNT/Sirefef.B,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {03 ce d1 f9 8b 34 88 03 75 08 89 4d fc 6a 0f bf } //01 00 
		$a_03_1 = {33 db 8b d3 fe c3 8a 04 33 02 d0 8a 24 32 88 24 33 02 e0 88 04 32 0f b6 c4 8a 04 30 30 07 47 e2 e3 90 09 05 00 b9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}