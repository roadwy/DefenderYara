
rule Virus_Win32_Expiro_MP_bit{
	meta:
		description = "Virus:Win32/Expiro.MP!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b f3 83 c6 30 8b 36 8b 3e 81 e7 df 00 df 00 8b 76 0b 03 f7 } //01 00 
		$a_03_1 = {4f 8b 39 85 ff 81 f7 90 01 04 3b df 89 3b 4f 4e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}