
rule TrojanSpy_BAT_Stealergen_MS_MTB{
	meta:
		description = "TrojanSpy:BAT/Stealergen.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {6f 52 4d 3d } //1 oRM=
		$a_01_1 = {41 70 70 65 6e 64 } //1 Append
		$a_01_2 = {45 6e 63 72 79 70 74 47 65 74 50 61 63 6b 61 67 65 50 72 6f 70 65 72 74 79 46 6c 61 67 73 } //1 EncryptGetPackagePropertyFlags
		$a_01_3 = {35 64 75 69 53 56 63 30 65 6d 46 46 6d 6a 76 46 6c 4b 57 36 52 33 63 4c 36 6e 41 } //1 5duiSVc0emFFmjvFlKW6R3cL6nA
		$a_01_4 = {53 68 61 64 6f 77 43 6f 70 79 44 69 72 65 63 74 6f 72 69 65 73 56 61 6c 75 65 43 72 65 61 74 65 } //1 ShadowCopyDirectoriesValueCreate
		$a_01_5 = {34 33 61 33 63 37 64 66 2d 61 61 37 39 2d 34 36 61 61 2d 39 65 39 35 2d 35 32 63 34 32 63 63 38 64 38 31 39 } //1 43a3c7df-aa79-46aa-9e95-52c42cc8d819
		$a_01_6 = {41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 44 65 73 6b 74 6f 70 5c 53 65 63 75 72 65 64 5c 41 75 74 6f 52 6f 62 6f 74 54 72 61 64 69 6e 67 53 6f 66 74 77 61 72 65 2e 70 64 62 } //1 Administrator\Desktop\Secured\AutoRobotTradingSoftware.pdb
		$a_01_7 = {53 6b 69 6c 6c 62 72 61 69 6e 73 } //1 Skillbrains
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}