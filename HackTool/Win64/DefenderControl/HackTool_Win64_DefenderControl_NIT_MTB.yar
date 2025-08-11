
rule HackTool_Win64_DefenderControl_NIT_MTB{
	meta:
		description = "HackTool:Win64/DefenderControl.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 65 66 65 6e 64 65 72 43 6f 6e 74 72 6f 6c } //2 DefenderControl
		$a_01_1 = {43 6f 6d 6d 61 6e 64 20 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 } //2 Command Add-MpPreference -ExclusionPath
		$a_01_2 = {64 43 6f 6e 74 72 6f 6c } //2 dControl
		$a_01_3 = {40 65 63 68 6f 20 6f 66 66 } //1 @echo off
		$a_01_4 = {63 6d 64 20 2f 63 20 64 65 6c } //1 cmd /c del
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}