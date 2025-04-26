
rule TrojanSpy_Win32_Banker_gen_C{
	meta:
		description = "TrojanSpy:Win32/Banker.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {45 78 65 4e 61 6d 65 4d 75 74 61 63 61 6f } //1 ExeNameMutacao
		$a_00_1 = {52 45 47 49 53 54 52 41 5f 49 4e 46 45 43 54 } //1 REGISTRA_INFECT
		$a_00_2 = {44 45 53 41 54 49 56 41 52 5f 46 49 52 45 57 41 4c 4c } //1 DESATIVAR_FIREWALL
		$a_02_3 = {6e 00 6f 00 74 00 66 00 69 00 72 00 69 00 [0-14] 2e 00 64 00 6c 00 6c 00 } //1
		$a_00_4 = {77 00 69 00 6e 00 64 00 76 00 78 00 73 00 77 00 65 00 71 00 } //1 windvxsweq
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}