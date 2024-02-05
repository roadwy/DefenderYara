
rule Trojan_Win32_Skraer_A{
	meta:
		description = "Trojan:Win32/Skraer.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 07 89 55 90 01 01 84 c0 74 90 01 01 3c 66 75 90 01 01 8b c7 33 c9 8a 14 02 8a 18 3a da 75 01 90 00 } //01 00 
		$a_03_1 = {8b 75 08 57 8d 86 90 01 02 00 00 50 8b 46 04 c7 45 90 01 01 00 00 00 00 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}