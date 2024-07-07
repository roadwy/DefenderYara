
rule VirTool_BAT_Subti_U_bit{
	meta:
		description = "VirTool:BAT/Subti.U!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 6c 70 76 62 6d 55 75 53 57 52 6c 62 6e 52 70 5a 6d 6c 6c 63 67 3d 3d } //1 OlpvbmUuSWRlbnRpZmllcg==
		$a_01_1 = {58 43 4e 69 61 57 35 6b 62 6d 46 74 5a 53 4d 75 5a 58 68 6c } //1 XCNiaW5kbmFtZSMuZXhl
		$a_01_2 = {49 32 4a 70 62 6d 52 66 63 32 56 30 64 43 4d 3d } //1 I2JpbmRfc2V0dCM=
		$a_01_3 = {4c 30 4d 67 59 32 68 76 61 57 4e 6c 49 43 39 44 49 46 6b 67 4c 30 34 67 4c 30 51 67 57 53 41 76 56 43 41 7a 49 43 59 67 52 47 56 73 49 43 49 3d } //1 L0MgY2hvaWNlIC9DIFkgL04gL0QgWSAvVCAzICYgRGVsICI=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}