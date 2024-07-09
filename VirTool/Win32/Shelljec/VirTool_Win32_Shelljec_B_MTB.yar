
rule VirTool_Win32_Shelljec_B_MTB{
	meta:
		description = "VirTool:Win32/Shelljec.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {8b c8 ff 15 ?? ?? ?? ?? 56 6a 00 68 ff ff 1f 00 ff } //1
		$a_00_1 = {6a 40 68 00 30 00 00 68 c8 00 00 00 6a 00 56 ff } //1
		$a_00_2 = {6a 00 68 c8 00 00 00 68 90 01 04 57 56 ff } //1
		$a_00_3 = {6a 00 6a 00 6a 00 57 6a 00 6a 00 56 ff } //1
		$a_02_4 = {6a ff 53 ff 15 ?? ?? ?? ?? 68 30 23 40 00 51 8b 0d a4 40 40 00 ba 9c 43 40 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}