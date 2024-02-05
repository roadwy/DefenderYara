
rule Trojan_Win32_Lukicsel_A{
	meta:
		description = "Trojan:Win32/Lukicsel.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {50 6a 00 6a 10 e8 90 01 04 8b d8 85 db 74 90 01 01 6a 00 6a 00 8b 44 24 90 01 01 50 8b 44 24 90 01 01 50 53 e8 90 01 04 68 e8 03 00 00 e8 90 01 04 6a 00 68 80 00 00 00 6a 03 6a 00 6a 00 68 00 00 00 c0 90 01 01 e8 90 01 04 83 f8 ff 74 90 00 } //01 00 
		$a_03_1 = {74 50 6a 00 8d 45 f0 50 6a 04 8b 45 08 50 56 e8 90 01 04 6a 00 8d 45 f0 50 6a 04 8b 45 fc 50 56 e8 90 00 } //01 00 
		$a_03_2 = {74 2a 8b 04 24 50 6a 00 6a 10 e8 90 01 04 8b d8 85 db 74 11 6a 00 6a 00 6a 00 8b 44 24 10 50 53 e8 90 01 04 53 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}