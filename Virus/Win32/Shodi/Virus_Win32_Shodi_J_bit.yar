
rule Virus_Win32_Shodi_J_bit{
	meta:
		description = "Virus:Win32/Shodi.J!bit,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 6f 62 62 2e 65 78 65 } //01 00 
		$a_01_1 = {61 6d 73 00 6f 67 72 00 53 68 6f 68 64 69 57 69 74 68 50 72 6f 67 72 61 6d 73 } //00 00 
	condition:
		any of ($a_*)
 
}