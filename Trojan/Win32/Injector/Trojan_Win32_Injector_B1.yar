
rule Trojan_Win32_Injector_B1{
	meta:
		description = "Trojan:Win32/Injector.B1,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 fc 90 90 90 90 8b 75 fc 03 75 f8 80 36 01 90 90 90 90 ff 45 fc 81 7d fc 90 01 02 00 00 75 e7 90 00 } //01 00 
		$a_00_1 = {43 6f 6e 74 72 6f 6c 5c 4b 65 79 62 6f 61 72 64 20 4c 61 79 6f 75 74 73 5c 25 2e 38 78 } //01 00  Control\Keyboard Layouts\%.8x
		$a_00_2 = {76 72 54 68 68 56 4f 4d 69 6c 75 } //00 00  vrThhVOMilu
	condition:
		any of ($a_*)
 
}