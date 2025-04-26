
rule HackTool_Win32_PplMedic_A{
	meta:
		description = "HackTool:Win32/PplMedic.A,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_01_0 = {79 d2 c1 b4 6e 96 e9 44 a9 c5 cc af 4a 77 02 3d } //1
		$a_03_1 = {c7 44 24 34 bb 1a b3 4e c7 44 24 ?? b4 f0 eb 43 44 8d 42 04 c7 44 24 ?? 1c b1 cb 32 } //10
		$a_80_2 = {57 61 61 53 4d 65 64 69 63 53 76 63 } //WaaSMedicSvc  1
		$a_80_3 = {4c 61 75 6e 63 68 44 65 74 65 63 74 69 6f 6e 4f 6e 6c 79 } //LaunchDetectionOnly  1
		$a_80_4 = {25 77 73 5c 55 55 53 5c 61 6d 64 36 34 5c 25 77 73 } //%ws\UUS\amd64\%ws  1
		$a_80_5 = {53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 54 79 70 65 4c 69 62 5c 25 77 73 5c 31 2e 30 5c 30 5c 57 69 6e 36 34 } //SOFTWARE\Classes\TypeLib\%ws\1.0\0\Win64  1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=14
 
}