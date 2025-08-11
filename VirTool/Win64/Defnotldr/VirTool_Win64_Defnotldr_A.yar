
rule VirTool_Win64_Defnotldr_A{
	meta:
		description = "VirTool:Win64/Defnotldr.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {6f 76 65 72 77 72 69 74 69 6e 67 20 [0-05] 2e 62 69 6e } //1
		$a_01_1 = {64 65 66 65 6e 64 6e 6f 74 } //1 defendnot
		$a_01_2 = {2d 66 72 6f 6d 2d 61 75 74 6f 72 75 6e } //1 -from-autorun
		$a_01_3 = {2d 2d 76 65 72 62 6f 73 65 } //1 --verbose
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}