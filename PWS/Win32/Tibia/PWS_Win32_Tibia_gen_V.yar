
rule PWS_Win32_Tibia_gen_V{
	meta:
		description = "PWS:Win32/Tibia.gen!V,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0b 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {c7 44 24 08 01 00 00 00 c7 44 24 04 90 01 04 c7 04 24 90 01 04 e8 90 01 04 83 ec 0c e8 90 01 04 e8 90 01 04 c7 04 24 88 13 00 00 e8 90 01 04 83 ec 04 eb ea 90 00 } //01 00 
		$a_00_1 = {46 67 79 74 74 66 72 6a } //01 00 
		$a_00_2 = {74 6b 6f 68 71 69 } //01 00 
		$a_00_3 = {46 47 47 76 69 64 65 } //01 00 
		$a_00_4 = {6d 74 70 6b 7a 58 6d 6b 6c 65 67 76 } //00 00 
	condition:
		any of ($a_*)
 
}