
rule Ransom_Win32_Mimic_YAA_MTB{
	meta:
		description = "Ransom:Win32/Mimic.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 08 00 00 "
		
	strings :
		$a_01_0 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 37 7a 61 2e 65 78 65 20 69 } //1 RunProgram="hidcon:7za.exe i
		$a_03_1 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 37 7a 61 2e 65 78 65 20 78 20 2d 79 20 2d 70 [0-14] 20 45 76 65 72 79 74 68 69 6e 67 36 34 2e 64 6c 6c } //10
		$a_01_2 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 5c 22 64 61 74 61 73 74 6f 72 65 40 63 79 62 65 72 66 65 61 72 2e 63 6f 6d 5f 6e 6f 20 67 75 69 2e 65 78 65 5c 22 20 25 53 66 78 56 61 72 43 6d 64 4c 69 6e 65 30 25 } //1 RunProgram="hidcon:\"datastore@cyberfear.com_no gui.exe\" %SfxVarCmdLine0%
		$a_01_3 = {47 55 49 46 6c 61 67 73 3d 22 32 2b 35 31 32 2b 38 31 39 32 } //1 GUIFlags="2+512+8192
		$a_01_4 = {4d 69 73 63 46 6c 61 67 73 3d 22 31 2b 32 2b 31 36 } //1 MiscFlags="1+2+16
		$a_01_5 = {47 55 49 4d 6f 64 65 3d 22 32 } //1 GUIMode="2
		$a_01_6 = {53 65 6c 66 44 65 6c 65 74 65 3d 22 31 } //1 SelfDelete="1
		$a_01_7 = {3b 21 40 49 6e 73 74 61 6c 6c 45 6e 64 40 } //1 ;!@InstallEnd@
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=17
 
}