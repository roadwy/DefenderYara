
rule Trojan_Win32_Helpud_S{
	meta:
		description = "Trojan:Win32/Helpud.S,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {7e 2e c7 45 f8 01 00 00 00 8b 45 fc 8b 55 f8 8a 5c 10 ff 80 c3 80 8d 45 f4 8b d3 e8 90 01 04 8b 55 f4 8b c7 e8 90 01 04 ff 45 f8 4e 75 d9 90 00 } //01 00 
		$a_03_1 = {84 c0 75 28 a1 90 01 04 e8 90 01 04 8b d8 8b cb ba 90 01 04 b8 0a 00 00 00 e8 90 01 04 84 c0 74 07 8b c3 e8 90 00 } //01 00 
		$a_03_2 = {84 c0 75 34 8d 45 e0 e8 90 01 04 8b 45 e0 50 a1 90 01 04 e8 90 01 04 8b d8 8b cb ba a4 43 40 00 b8 0a 00 00 00 e8 90 01 04 84 c0 74 07 8b c3 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}