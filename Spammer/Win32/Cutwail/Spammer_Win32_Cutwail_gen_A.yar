
rule Spammer_Win32_Cutwail_gen_A{
	meta:
		description = "Spammer:Win32/Cutwail.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 17 52 e8 90 01 02 00 00 0f b6 05 90 01 03 00 0f b6 0d 90 01 03 00 50 a1 90 01 03 00 51 0f b6 d4 52 0f b6 c0 50 68 90 00 } //01 00 
		$a_02_1 = {6a 17 51 e8 90 01 02 00 00 0f b6 15 90 01 03 13 0f b6 05 90 01 03 13 52 50 a1 90 01 03 13 0f b6 cc 51 0f b6 d0 52 68 90 00 } //01 00 
		$a_02_2 = {6a 17 ff 70 0c e8 90 01 02 ff ff 0f b6 05 90 01 04 50 0f b6 05 90 01 04 50 a1 90 01 04 0f b6 cc 51 0f b6 c0 50 68 90 00 } //01 00 
		$a_02_3 = {6a 17 ff 77 0c e8 90 01 02 ff ff 6a 12 e8 90 01 02 ff ff 89 45 fc 0f b6 05 90 01 04 50 0f b6 05 90 01 04 50 a1 90 01 04 0f b6 cc 51 0f b6 c0 50 68 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}