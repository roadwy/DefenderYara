
rule Trojan_Win64_SalatStealer_ABS_MTB{
	meta:
		description = "Trojan:Win64/SalatStealer.ABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_03_0 = {4d 01 d3 44 01 d1 44 01 d2 45 01 d0 49 ff c2 49 0f af fa 48 01 de 49 d3 c3 89 d1 48 d3 cf 44 89 c1 48 d3 c6 49 31 fb 48 31 f7 48 81 f6 ?? ?? ?? ?? 48 ff cb eb } //6
		$a_80_1 = {73 76 63 68 6f 73 74 64 77 6d 61 75 64 69 6f 64 67 73 65 61 72 63 68 69 6e 64 65 78 65 72 27 27 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 27 27 20 2d 46 6f 72 63 65 } //svchostdwmaudiodgsearchindexer''Add-MpPreference -ExclusionPath '' -Force  1
		$a_80_2 = {73 65 61 72 63 68 69 6e 64 65 78 65 72 27 27 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 27 27 20 2d 46 6f 72 63 65 } //searchindexer''Add-MpPreference -ExclusionPath '' -Force  1
		$a_80_3 = {41 50 50 44 41 54 41 50 72 6f 67 72 61 6d 44 61 74 61 4d 69 63 72 6f 73 6f 66 74 57 69 6e 64 6f 77 73 53 65 63 75 72 69 74 79 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 } //APPDATAProgramDataMicrosoftWindowsSecurityC:\ProgramDataC:\Users\Public  1
		$a_80_4 = {48 44 55 49 4c 50 47 54 5c 5c 42 78 72 67 64 68 64 75 69 5c 5c 4c 78 63 73 64 6c 68 21 53 74 75 74 63 73 74 67 5c 5c 54 6d 72 61 6a 68 78 64 63 68 5c 5c 45 70 69 77 68 41 50 50 44 41 54 41 50 72 6f 67 72 61 6d 44 61 74 61 4d 69 63 72 6f 73 6f 66 74 57 69 6e 64 6f 77 73 53 65 63 75 72 69 74 79 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 } //HDUILPGT\\Bxrgdhdui\\Lxcsdlh!Stutcstg\\Tmrajhxdch\\EpiwhAPPDATAProgramDataMicrosoftWindowsSecurityC:\ProgramDataC:\Users\Public  1
	condition:
		((#a_03_0  & 1)*6+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=8
 
}