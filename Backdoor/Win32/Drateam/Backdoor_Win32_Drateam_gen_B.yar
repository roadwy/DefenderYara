
rule Backdoor_Win32_Drateam_gen_B{
	meta:
		description = "Backdoor:Win32/Drateam.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff ff ff ff 12 00 00 00 4d 53 47 7c b8 c3 c4 bf c2 bc b2 bb b4 e6 d4 da a3 a1 00 } //01 00 
		$a_01_1 = {ff ff ff ff 14 00 00 00 4d 53 47 7c c7 fd b6 af c6 f7 ce de b7 a8 b7 c3 ce ca a3 a1 00 } //01 00 
		$a_01_2 = {ff ff ff ff 0f 00 00 00 77 71 32 6c 79 66 2e 67 69 63 70 2e 6e 65 74 00 } //01 00 
		$a_00_3 = {43 4f 4e 4e 45 43 54 45 44 3f 0a 00 } //00 00 
	condition:
		any of ($a_*)
 
}