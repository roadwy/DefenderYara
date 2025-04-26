
rule HackTool_Win32_Keygen_R_MTB{
	meta:
		description = "HackTool:Win32/Keygen.R!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 0b 00 00 "
		
	strings :
		$a_01_0 = {6b 65 79 67 65 6e 2e 65 78 65 } //1 keygen.exe
		$a_01_1 = {65 79 67 65 6e 2e 65 78 65 } //1 eygen.exe
		$a_01_2 = {52 32 52 53 31 4b 47 32 2e 64 6c 6c } //1 R2RS1KG2.dll
		$a_01_3 = {42 41 53 53 4d 4f 44 2e 64 6c 6c } //1 BASSMOD.dll
		$a_01_4 = {62 67 6d 2e 78 6d } //1 bgm.xm
		$a_01_5 = {53 74 75 64 69 6f 4f 6e 65 20 4b 65 79 47 65 6e } //1 StudioOne KeyGen
		$a_01_6 = {68 73 70 33 64 65 62 75 67 2e 64 6c 6c } //1 hsp3debug.dll
		$a_01_7 = {41 62 6c 65 74 6f 6e 20 31 30 20 4b 65 79 47 65 6e } //1 Ableton 10 KeyGen
		$a_01_8 = {54 72 61 6b 74 6f 72 20 50 72 6f 20 33 20 4b 65 79 47 65 6e } //1 Traktor Pro 3 KeyGen
		$a_01_9 = {4e 61 74 69 76 65 20 49 6e 73 74 72 75 6d 65 6e 74 73 20 4b 65 79 47 65 6e } //1 Native Instruments KeyGen
		$a_01_10 = {47 65 6e 65 72 61 74 65 4c 69 63 65 6e 73 65 } //1 GenerateLicense
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=6
 
}