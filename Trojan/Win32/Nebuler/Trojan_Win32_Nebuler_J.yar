
rule Trojan_Win32_Nebuler_J{
	meta:
		description = "Trojan:Win32/Nebuler.J,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 53 53 4d 53 47 53 00 25 73 5c 25 73 00 00 00 50 49 44 00 4c 49 44 00 65 6d 70 74 79 00 00 00 5c 57 69 6e 49 6e 69 74 2e 49 6e 69 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Nebuler_J_2{
	meta:
		description = "Trojan:Win32/Nebuler.J,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {73 29 8b 8d 90 01 04 0f b6 94 90 01 05 8b 85 90 01 04 0f b6 88 90 01 04 33 ca 8b 95 90 01 04 88 8a 90 00 } //01 00 
		$a_01_1 = {b8 68 58 4d 56 b9 14 00 00 00 66 ba 58 56 ed } //00 00 
	condition:
		any of ($a_*)
 
}