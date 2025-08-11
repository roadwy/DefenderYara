
rule Trojan_Win32_Delf_OKO_MTB{
	meta:
		description = "Trojan:Win32/Delf.OKO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 "
		
	strings :
		$a_81_0 = {53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 ShellExecute
		$a_81_1 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 autorun.inf
		$a_81_2 = {53 79 6e 61 70 74 69 63 73 2e 65 78 65 } //1 Synaptics.exe
		$a_81_3 = {49 6e 6a 65 63 74 69 6e 67 } //2 Injecting
		$a_81_4 = {2e 78 6c 73 78 } //2 .xlsx
		$a_81_5 = {41 75 74 6f 20 55 70 64 61 74 65 20 2d 3e 20 41 63 74 69 76 65 } //1 Auto Update -> Active
		$a_81_6 = {41 75 74 6f 20 55 70 64 61 74 65 20 2d 3e 20 44 65 61 63 74 69 76 65 } //1 Auto Update -> Deactive
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=9
 
}