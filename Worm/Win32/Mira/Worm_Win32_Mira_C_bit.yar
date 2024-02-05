
rule Worm_Win32_Mira_C_bit{
	meta:
		description = "Worm:Win32/Mira.C!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 85 79 ff ff ff 3a c6 85 7a ff ff ff 5c c6 85 7b ff ff ff 4d c6 85 7c ff ff ff 69 c6 85 7d ff ff ff 72 c6 85 7e ff ff ff 61 } //01 00 
		$a_01_1 = {53 61 61 61 61 6c 61 6d 6d } //00 00 
	condition:
		any of ($a_*)
 
}