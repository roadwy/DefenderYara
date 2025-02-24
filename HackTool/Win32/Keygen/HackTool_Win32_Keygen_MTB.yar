
rule HackTool_Win32_Keygen_MTB{
	meta:
		description = "HackTool:Win32/Keygen!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {47 65 6e 65 72 61 74 65 } //Generate  1
		$a_80_1 = {6b 65 79 67 65 6e 6e 65 64 20 62 79 20 69 63 65 2f 42 52 44 } //keygenned by ice/BRD  1
		$a_80_2 = {2d 20 4b 65 79 67 65 6e 20 62 79 20 42 52 44 } //- Keygen by BRD  1
		$a_80_3 = {62 6c 61 63 6b 20 72 69 64 65 72 73 } //black riders  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule HackTool_Win32_Keygen_MTB_2{
	meta:
		description = "HackTool:Win32/Keygen!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_80_0 = {54 45 41 4d 20 46 46 46 } //TEAM FFF  1
		$a_80_1 = {72 61 72 72 65 67 2e 6b 65 79 } //rarreg.key  1
		$a_80_2 = {6b 65 79 67 65 6e } //keygen  1
		$a_80_3 = {42 55 54 54 4f 4e 42 4f 58 57 49 4e 44 4f 57 } //BUTTONBOXWINDOW  1
		$a_00_4 = {6b 65 6e 74 70 77 40 6e 6f 72 77 69 63 68 2e 6e 65 74 } //1 kentpw@norwich.net
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}
rule HackTool_Win32_Keygen_MTB_3{
	meta:
		description = "HackTool:Win32/Keygen!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4b 65 79 67 65 6e } //1 Keygen
		$a_01_1 = {6b 65 79 73 68 6f 74 } //1 keyshot
		$a_01_2 = {4b 65 79 4d 65 73 68 69 6e 67 } //1 KeyMeshing
		$a_01_3 = {4c 75 78 69 6f 6e 20 4b 65 79 73 68 6f 74 } //1 Luxion Keyshot
		$a_01_4 = {72 61 6e 64 6f 6d 20 6e 75 6d 62 65 72 20 67 65 6e 65 72 61 74 6f 72 } //1 random number generator
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule HackTool_Win32_Keygen_MTB_4{
	meta:
		description = "HackTool:Win32/Keygen!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {42 75 6e 64 6c 65 } //1 Bundle
		$a_01_1 = {4b 65 79 67 65 6e } //1 Keygen
		$a_01_2 = {4b 65 79 67 65 6e 4c 61 79 65 72 } //1 KeygenLayer
		$a_01_3 = {50 72 65 73 73 20 67 65 6e 65 72 61 74 65 } //1 Press generate
		$a_01_4 = {43 43 6c 65 61 6e 65 72 } //1 CCleaner
		$a_01_5 = {50 69 72 69 66 6f 72 6d 20 4d 75 6c 74 69 47 65 6e } //1 Piriform MultiGen
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule HackTool_Win32_Keygen_MTB_5{
	meta:
		description = "HackTool:Win32/Keygen!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {58 2d 46 4f 52 43 45 } //1 X-FORCE
		$a_01_1 = {52 49 50 50 47 72 61 7a 65 79 20 2f 20 50 48 46 } //1 RIPPGrazey / PHF
		$a_01_2 = {43 4f 4e 56 47 72 61 7a 65 79 20 2f 20 50 48 46 } //1 CONVGrazey / PHF
		$a_01_3 = {70 72 65 73 73 20 47 65 6e 65 72 61 74 65 } //1 press Generate
		$a_01_4 = {4a 61 6d 43 72 61 63 6b 65 72 50 72 6f } //1 JamCrackerPro
		$a_01_5 = {6c 69 76 65 20 4b 65 79 6d 61 6b 65 72 } //1 live Keymaker
		$a_01_6 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 70 61 74 63 68 65 64 21 } //1 Successfully patched!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
rule HackTool_Win32_Keygen_MTB_6{
	meta:
		description = "HackTool:Win32/Keygen.MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {6b 65 79 67 65 6e 2e 65 78 65 } //keygen.exe  1
		$a_80_1 = {43 6f 6e 74 61 69 6e 73 4b 65 79 } //ContainsKey  1
		$a_80_2 = {4b 65 79 6d 61 6b 65 72 } //Keymaker  1
		$a_80_3 = {48 65 6c 70 4b 65 79 77 6f 72 64 41 74 74 72 69 62 75 74 65 } //HelpKeywordAttribute  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}