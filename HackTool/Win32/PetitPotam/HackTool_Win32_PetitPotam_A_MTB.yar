
rule HackTool_Win32_PetitPotam_A_MTB{
	meta:
		description = "HackTool:Win32/PetitPotam.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 08 4b 4f 00 6a 64 8d ?? ?? ?? ?? ?? 51 e8 ?? ?? ?? ?? 83 c4 10 8b f4 8d ?? ?? ?? ?? ?? 50 6a 00 8b 0d 58 4a 4f 00 51 8d ?? ?? ?? ?? ?? 52 68 14 4b 4f 00 a1 54 ?? ?? ?? 50 ff 15 } //1
		$a_01_1 = {6a 00 6a 00 8d 45 f8 50 68 00 04 00 00 8b 4d 08 51 6a 00 68 00 13 00 00 ff 15 } //1
		$a_01_2 = {83 c4 08 b8 04 00 00 00 c1 e0 00 8b 4d 0c 8b 14 01 52 68 b8 4c 4f 00 6a 64 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}