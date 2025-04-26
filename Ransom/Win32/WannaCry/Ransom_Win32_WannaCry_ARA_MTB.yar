
rule Ransom_Win32_WannaCry_ARA_MTB{
	meta:
		description = "Ransom:Win32/WannaCry.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 77 63 72 79 } //2 .wcry
		$a_01_1 = {72 65 67 20 61 64 64 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 } //2 reg add HKCU\Software
		$a_01_2 = {44 69 73 61 62 6c 65 43 4d 44 } //2 DisableCMD
		$a_01_3 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //2 DisableTaskMgr
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}