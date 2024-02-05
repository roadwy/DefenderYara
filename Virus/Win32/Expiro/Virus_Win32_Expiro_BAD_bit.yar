
rule Virus_Win32_Expiro_BAD_bit{
	meta:
		description = "Virus:Win32/Expiro.BAD!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b da 83 c3 30 8b 1b 8b 03 81 e0 df 00 df 00 8b 5b 0b 03 d8 } //01 00 
		$a_03_1 = {8d 03 8b 06 85 c3 35 90 01 04 39 c6 89 02 29 d8 83 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}