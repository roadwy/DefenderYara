
rule VirTool_Win32_Tater_B_MTB{
	meta:
		description = "VirTool:Win32/Tater.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {50 72 69 6e 74 53 70 6f 6f 66 65 72 } //1 PrintSpoofer
		$a_81_1 = {53 68 61 72 70 50 6f 74 61 74 6f } //1 SharpPotato
		$a_81_2 = {50 6f 74 61 74 6f 41 50 49 } //1 PotatoAPI
		$a_81_3 = {70 69 70 65 5c 73 70 6f 6f 6c 73 73 } //1 pipe\spoolss
		$a_81_4 = {70 69 70 65 5c 73 72 76 73 76 63 } //1 pipe\srvsvc
		$a_81_5 = {45 64 70 52 70 63 52 6d 73 47 65 74 43 6f 6e 74 61 69 6e 65 72 49 64 65 6e 74 69 74 79 } //1 EdpRpcRmsGetContainerIdentity
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}