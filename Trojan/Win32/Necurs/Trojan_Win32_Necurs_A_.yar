
rule Trojan_Win32_Necurs_A_{
	meta:
		description = "Trojan:Win32/Necurs.A!!Necurs.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4b 3c 03 cb 8b 81 a0 00 00 00 8b 91 a4 00 00 00 89 55 f8 85 c0 74 63 } //01 00 
		$a_01_1 = {8b 41 3c 6a 00 ff 74 08 50 51 e8 02 ff ff ff 83 c4 0c 5d c3 } //01 00 
		$a_03_2 = {35 de c0 ad de 89 45 90 01 01 ff 15 90 01 04 33 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}