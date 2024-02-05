
rule Trojan_Win32_Koorema_A{
	meta:
		description = "Trojan:Win32/Koorema.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 c6 02 e9 89 42 01 8d 7a 05 7e 13 8b d1 c1 e9 02 b8 cc cc cc cc f3 ab 8b ca 83 e1 03 f3 aa } //01 00 
		$a_03_1 = {c7 06 45 34 52 74 ff 15 90 01 04 8d 46 14 50 c7 00 9c 00 00 00 ff 15 90 00 } //01 00 
		$a_00_2 = {72 75 6e 64 6c 6c 33 32 20 22 25 73 22 2c 58 46 52 65 73 74 61 72 74 00 5c 69 6e 65 74 73 72 76 5c 77 61 6d 72 65 67 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}