
rule Trojan_Win32_Helpud_A{
	meta:
		description = "Trojan:Win32/Helpud.A,SIGNATURE_TYPE_PEHSTR_EXT,11 00 10 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 53 55 55 44 4c 00 } //01 00 
		$a_00_1 = {57 53 58 49 48 55 44 53 00 } //0a 00 
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //05 00  SOFTWARE\Borland\Delphi
		$a_03_3 = {7e 2e c7 45 f8 01 00 00 00 8b 45 fc 8b 55 f8 8a 5c 10 ff 80 c3 80 8d 45 f4 8b d3 e8 90 01 04 8b 55 f4 8b c7 e8 90 01 04 ff 45 f8 4e 75 d9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}