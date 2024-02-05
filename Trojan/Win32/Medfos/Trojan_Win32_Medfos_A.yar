
rule Trojan_Win32_Medfos_A{
	meta:
		description = "Trojan:Win32/Medfos.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {c6 45 e0 69 90 03 04 07 c6 45 e1 65 e9 90 16 c6 45 e1 65 90 03 04 07 c6 45 e2 78 e9 90 16 c6 45 e2 78 90 00 } //01 00 
		$a_03_1 = {68 00 30 00 00 90 03 05 08 68 00 b0 04 00 e9 90 16 68 00 b0 04 00 90 00 } //01 00 
		$a_03_2 = {69 ff c8 00 00 00 90 03 01 04 57 e9 90 16 57 90 03 04 07 a2 90 01 04 e9 90 16 a2 90 01 04 90 03 02 05 ff 15 e9 90 16 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Medfos_A_2{
	meta:
		description = "Trojan:Win32/Medfos.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 5c 39 48 90 03 02 05 32 d8 e9 90 16 32 d8 90 03 03 06 88 1c 32 e9 90 16 88 1c 32 90 03 01 04 42 e9 90 16 42 90 03 02 05 fe c0 e9 90 16 fe c0 90 03 03 06 83 ff 02 e9 90 16 83 ff 02 90 00 } //01 00 
		$a_03_1 = {c6 45 f3 70 90 03 04 07 c6 45 f4 6c e9 90 16 c6 45 f4 6c 90 03 04 07 c6 45 f5 6f e9 90 16 c6 45 f5 6f 90 00 } //01 00 
		$a_03_2 = {69 c0 e8 03 00 00 90 03 04 07 a3 90 01 04 e9 90 16 a3 90 01 04 90 03 01 04 c3 e9 90 16 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}