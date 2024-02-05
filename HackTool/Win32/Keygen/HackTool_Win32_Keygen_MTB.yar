
rule HackTool_Win32_Keygen_MTB{
	meta:
		description = "HackTool:Win32/Keygen!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {54 45 41 4d 20 46 46 46 } //TEAM FFF  01 00 
		$a_80_1 = {72 61 72 72 65 67 2e 6b 65 79 } //rarreg.key  01 00 
		$a_80_2 = {6b 65 79 67 65 6e } //keygen  01 00 
		$a_80_3 = {42 55 54 54 4f 4e 42 4f 58 57 49 4e 44 4f 57 } //BUTTONBOXWINDOW  01 00 
		$a_00_4 = {6b 65 6e 74 70 77 40 6e 6f 72 77 69 63 68 2e 6e 65 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule HackTool_Win32_Keygen_MTB_2{
	meta:
		description = "HackTool:Win32/Keygen!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 65 79 67 65 6e } //01 00 
		$a_01_1 = {6b 65 79 73 68 6f 74 } //01 00 
		$a_01_2 = {4b 65 79 4d 65 73 68 69 6e 67 } //01 00 
		$a_01_3 = {4c 75 78 69 6f 6e 20 4b 65 79 73 68 6f 74 } //01 00 
		$a_01_4 = {72 61 6e 64 6f 6d 20 6e 75 6d 62 65 72 20 67 65 6e 65 72 61 74 6f 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule HackTool_Win32_Keygen_MTB_3{
	meta:
		description = "HackTool:Win32/Keygen!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 75 6e 64 6c 65 } //01 00 
		$a_01_1 = {4b 65 79 67 65 6e } //01 00 
		$a_01_2 = {4b 65 79 67 65 6e 4c 61 79 65 72 } //01 00 
		$a_01_3 = {50 72 65 73 73 20 67 65 6e 65 72 61 74 65 } //01 00 
		$a_01_4 = {43 43 6c 65 61 6e 65 72 } //01 00 
		$a_01_5 = {50 69 72 69 66 6f 72 6d 20 4d 75 6c 74 69 47 65 6e } //00 00 
	condition:
		any of ($a_*)
 
}
rule HackTool_Win32_Keygen_MTB_4{
	meta:
		description = "HackTool:Win32/Keygen!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 2d 46 4f 52 43 45 } //01 00 
		$a_01_1 = {52 49 50 50 47 72 61 7a 65 79 20 2f 20 50 48 46 } //01 00 
		$a_01_2 = {43 4f 4e 56 47 72 61 7a 65 79 20 2f 20 50 48 46 } //01 00 
		$a_01_3 = {70 72 65 73 73 20 47 65 6e 65 72 61 74 65 } //01 00 
		$a_01_4 = {4a 61 6d 43 72 61 63 6b 65 72 50 72 6f } //01 00 
		$a_01_5 = {6c 69 76 65 20 4b 65 79 6d 61 6b 65 72 } //01 00 
		$a_01_6 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 70 61 74 63 68 65 64 21 } //00 00 
	condition:
		any of ($a_*)
 
}