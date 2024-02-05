
rule Trojan_Win32_Urelas_A{
	meta:
		description = "Trojan:Win32/Urelas.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 a4 1c 04 10 8d 55 ec 52 e8 00 dd fc ff 83 c4 10 c6 45 fc 00 8d 4d e8 e8 81 de fc ff 51 8b c4 89 65 e4 50 e8 55 03 00 00 83 c4 04 89 45 d4 8b 4d d4 89 4d d0 c6 45 fc 02 51 8b cc 89 65 e0 8d 55 ec 52 e8 16 d9 fc ff 89 45 cc c6 45 fc 00 e8 8a fd ff ff } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Urelas_A_2{
	meta:
		description = "Trojan:Win32/Urelas.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_11_0 = {69 6e 64 6f 77 20 55 73 72 65 20 4c 6f 67 69 6e 01 } //00 18 
		$a_4c_1 = {41 } //00 53 
		$a_00_3 = {45 00 52 00 2e 00 65 00 78 00 65 00 01 00 1e 01 24 00 24 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 58 00 70 00 2e 00 62 00 61 00 74 00 01 00 0a 01 09 5f 50 4d 4e 55 4d 42 45 52 00 00 5d 04 00 00 9a 98 02 80 5c 21 00 00 9b } //98 02 
	condition:
		any of ($a_*)
 
}