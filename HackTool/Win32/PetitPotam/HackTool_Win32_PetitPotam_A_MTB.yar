
rule HackTool_Win32_PetitPotam_A_MTB{
	meta:
		description = "HackTool:Win32/PetitPotam.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 08 4b 4f 00 6a 64 8d 90 01 05 51 e8 90 01 04 83 c4 10 8b f4 8d 90 01 05 50 6a 00 8b 0d 58 4a 4f 00 51 8d 90 01 05 52 68 14 4b 4f 00 a1 54 90 01 03 50 ff 15 90 00 } //01 00 
		$a_01_1 = {6a 00 6a 00 8d 45 f8 50 68 00 04 00 00 8b 4d 08 51 6a 00 68 00 13 00 00 ff 15 } //01 00 
		$a_01_2 = {83 c4 08 b8 04 00 00 00 c1 e0 00 8b 4d 0c 8b 14 01 52 68 b8 4c 4f 00 6a 64 } //00 00 
	condition:
		any of ($a_*)
 
}