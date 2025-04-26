
rule Trojan_Win64_IcedId_QW_MTB{
	meta:
		description = "Trojan:Win64/IcedId.QW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {57 61 76 54 69 70 53 61 6d 70 6c 65 2e 70 64 62 } //WavTipSample.pdb  3
		$a_80_1 = {50 61 74 68 46 69 6e 64 45 78 74 65 6e 73 69 6f 6e 41 } //PathFindExtensionA  3
		$a_80_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //ShellExecuteA  3
		$a_80_3 = {57 61 76 54 69 70 53 61 6d 70 6c 65 2e 64 6c 6c } //WavTipSample.dll  3
		$a_80_4 = {52 65 73 75 6d 65 53 65 72 76 65 72 } //ResumeServer  3
		$a_80_5 = {53 74 61 72 74 53 65 72 76 65 72 } //StartServer  3
		$a_80_6 = {53 74 6f 70 53 65 72 76 65 72 } //StopServer  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}