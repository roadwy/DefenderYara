
rule Virus_Win32_Expiro_BAA_bit{
	meta:
		description = "Virus:Win32/Expiro.BAA!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b d8 83 c3 30 8b 1b 8b 0b 81 e1 df 00 df 00 8b 5b 0b 03 d9 } //01 00 
		$a_03_1 = {41 8b 0e 85 c3 81 f1 90 01 04 3b d9 89 08 89 c1 4b 4b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}