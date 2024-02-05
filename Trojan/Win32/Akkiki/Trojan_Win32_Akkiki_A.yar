
rule Trojan_Win32_Akkiki_A{
	meta:
		description = "Trojan:Win32/Akkiki.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {c7 84 24 fc 02 00 00 0b 00 00 00 8b c1 8b f7 c1 e9 02 bf ec a9 40 00 f3 a5 8b c8 33 c0 83 e1 03 f3 a4 } //01 00 
		$a_00_1 = {20 2f 76 20 2f 79 20 2f 72 20 2f 66 20 6c 73 6f 6c 6c 6f } //01 00 
		$a_02_2 = {0f be 34 10 83 c6 1c 81 fe 96 00 00 00 0f 87 e2 00 00 00 33 c9 8a 8e 90 01 03 00 ff 24 8d 90 01 03 00 c6 04 10 53 e9 ca 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}