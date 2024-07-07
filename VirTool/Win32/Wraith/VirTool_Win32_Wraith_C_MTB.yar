
rule VirTool_Win32_Wraith_C_MTB{
	meta:
		description = "VirTool:Win32/Wraith.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_81_0 = {57 72 61 69 74 68 29 2e 53 70 61 77 6e } //1 Wraith).Spawn
		$a_81_1 = {57 72 61 69 74 68 29 2e 4b 69 6c 6c } //1 Wraith).Kill
		$a_81_2 = {57 72 61 69 74 68 29 2e 53 48 4d } //1 Wraith).SHM
		$a_81_3 = {57 72 61 69 74 68 29 2e 4d 6f 64 73 52 65 67 } //1 Wraith).ModsReg
		$a_81_4 = {57 72 61 69 74 68 29 2e 63 61 74 63 68 } //1 Wraith).catch
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=4
 
}