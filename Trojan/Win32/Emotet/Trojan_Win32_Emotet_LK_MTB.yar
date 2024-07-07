
rule Trojan_Win32_Emotet_LK_MTB{
	meta:
		description = "Trojan:Win32/Emotet.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {45 66 70 78 78 6c 73 65 65 6e 6e 2e 64 6c 6c } //1 Efpxxlseenn.dll
		$a_81_1 = {43 66 65 72 70 67 67 6c 44 72 62 } //1 CferpgglDrb
		$a_81_2 = {46 64 64 70 70 66 65 77 2e 70 64 62 } //1 Fddppfew.pdb
		$a_81_3 = {53 65 6c 66 20 65 78 } //1 Self ex
		$a_81_4 = {74 65 73 74 61 70 70 2e 65 78 65 } //1 testapp.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}