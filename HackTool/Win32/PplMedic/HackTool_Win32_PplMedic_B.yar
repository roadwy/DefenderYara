
rule HackTool_Win32_PplMedic_B{
	meta:
		description = "HackTool:Win32/PplMedic.B,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {79 d2 c1 b4 6e 96 e9 44 a9 c5 cc af 4a 77 02 3d } //1
		$a_03_1 = {c7 44 24 34 bb 1a b3 4e c7 44 24 ?? b4 f0 eb 43 44 8d 42 04 c7 44 24 ?? 1c b1 cb 32 } //10
		$a_80_2 = {5c 43 61 74 52 6f 6f 74 5c 7b 46 37 35 30 45 36 43 33 2d 33 38 45 45 2d 31 31 44 31 2d 38 35 45 35 2d 30 30 43 30 34 46 43 32 39 35 45 45 7d } //\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}  1
		$a_80_3 = {4c 61 75 6e 63 68 44 65 74 65 63 74 69 6f 6e 4f 6e 6c 79 } //LaunchDetectionOnly  1
		$a_80_4 = {57 61 61 53 4d 65 64 69 63 4c 6f 67 6f 6e 53 65 73 73 69 6f 6e 50 69 70 65 } //WaaSMedicLogonSessionPipe  1
		$a_80_5 = {24 43 49 2e 43 41 54 41 4c 4f 47 48 49 4e 54 } //$CI.CATALOGHINT  1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=12
 
}