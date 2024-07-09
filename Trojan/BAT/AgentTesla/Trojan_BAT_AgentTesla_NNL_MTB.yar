
rule Trojan_BAT_AgentTesla_NNL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NNL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f 3f 05 00 0a 17 73 ?? ?? ?? 0a 0c 08 02 16 02 8e 69 6f ?? ?? ?? 0a } //5
		$a_01_1 = {4d 47 2e 4f 66 66 69 63 65 2e 45 64 69 74 6f 72 2e 66 72 6d 4d 61 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 MG.Office.Editor.frmMain.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_NNL_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NNL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {1d 09 1d 09 67 00 4c 00 1d 09 1d 09 38 00 2f 00 2f 00 1d 09 1d 09 1d 09 1d 09 45 00 1d 09 1d 09 1d 09 1d 09 4d 00 1d 09 1d 09 51 00 71 00 56 00 54 00 01 } //1
		$a_01_1 = {4e 00 49 00 66 00 4c 00 6c 00 59 00 42 00 1d 09 1d 09 1d 09 77 00 73 00 34 00 45 00 1d 09 1d 09 1d 09 4d 00 55 00 6a 00 59 00 64 00 52 00 61 00 4f 00 43 00 1d 09 } //1 NIfLlYBझझझws4EझझझMUjYdRaOCझ
		$a_01_2 = {66 00 77 00 44 00 57 00 1d 09 1d 09 45 00 1d 09 45 00 1d 09 43 00 49 00 1d 09 64 00 77 00 42 00 42 00 51 00 43 00 48 00 1d 09 4e 00 67 00 1d 09 1d 09 51 00 1d 09 51 00 1d 09 } //1 fwDWझझEझEझCIझdwBBQCHझNgझझQझQझ
		$a_01_3 = {1d 09 1d 09 1d 09 1d 09 1d 09 1d 09 1d 09 1d 09 1d 09 1d 09 1d 09 1d 09 1d 09 1d 09 1d 09 1d 09 1d 09 3d 00 3d } //1
		$a_01_4 = {53 00 68 00 61 00 72 00 70 00 53 00 74 00 72 00 75 00 63 00 74 00 75 00 72 00 65 00 73 00 2e 00 4d 00 61 00 69 00 6e 00 2e 00 53 00 6f 00 72 00 74 00 48 00 65 00 6c 00 70 00 65 00 72 } //1
		$a_01_5 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_80_6 = {46 72 6f 6d 42 61 73 65 36 34 } //FromBase64  1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}