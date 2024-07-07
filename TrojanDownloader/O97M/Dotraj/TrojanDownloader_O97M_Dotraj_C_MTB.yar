
rule TrojanDownloader_O97M_Dotraj_C_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dotraj.C!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {43 61 6c 6c 42 79 4e 61 6d 65 20 53 75 62 50 72 6f 70 65 72 74 79 2c 20 22 73 22 20 2b 20 50 72 6f 6a 65 63 74 54 72 61 6e 73 66 6f 72 6d 61 74 69 6f 6e 20 2b 20 22 69 6c 65 22 2c } //1 CallByName SubProperty, "s" + ProjectTransformation + "ile",
		$a_00_1 = {43 61 6c 6c 42 79 4e 61 6d 65 20 72 70 74 50 72 6f 62 6c 65 6d 2c 20 73 54 56 4f 4c 2e 54 6f 67 67 6c 65 42 75 74 74 6f 6e 31 2e 43 61 70 74 69 6f 6e 2c 20 56 62 4d 65 74 68 6f 64 } //1 CallByName rptProblem, sTVOL.ToggleButton1.Caption, VbMethod
		$a_00_2 = {52 61 69 73 65 20 76 62 4f 62 6a 65 63 74 45 72 72 6f 72 20 2b 20 35 35 35 2c 20 22 35 22 2c 20 22 35 35 22 } //1 Raise vbObjectError + 555, "5", "55"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}