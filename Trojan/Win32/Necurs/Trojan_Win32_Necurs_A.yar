
rule Trojan_Win32_Necurs_A{
	meta:
		description = "Trojan:Win32/Necurs.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 00 5c 00 2e 00 5c 00 4e 00 74 00 53 00 65 00 63 00 75 00 72 00 65 00 53 00 79 00 73 00 } //01 00 
		$a_01_1 = {8d 14 90 03 d2 c1 ce 0d 33 f2 03 c6 88 19 41 ff 4d 0c 75 e1 } //01 00 
		$a_03_2 = {35 de c0 ad de 89 45 90 01 01 ff 15 90 01 04 33 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}