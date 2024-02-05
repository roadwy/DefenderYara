
rule Ransom_Win32_Crowti_A{
	meta:
		description = "Ransom:Win32/Crowti.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 a0 00 00 00 e8 18 00 00 00 59 89 45 fc 83 7d fc 00 74 90 01 01 8b 45 fc 2d 90 01 04 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Crowti_A_2{
	meta:
		description = "Ransom:Win32/Crowti.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 04 68 00 30 00 00 8d 4d 90 01 01 51 6a 00 68 90 01 04 6a ff ff 55 90 00 } //01 00 
		$a_03_1 = {0f b7 51 2c d1 ea 52 8b 45 90 01 01 8b 48 30 51 e8 90 01 04 83 c4 08 3b 45 08 75 08 8b 55 90 01 01 8b 42 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}