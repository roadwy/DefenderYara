
rule VirTool_Win32_Williez_A_MTB{
	meta:
		description = "VirTool:Win32/Williez.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {67 69 74 68 75 62 2e 63 6f 6d 2f 4e 65 30 6e 64 30 67 } //1 github.com/Ne0nd0g
		$a_81_1 = {67 69 74 68 75 62 2e 63 6f 6d 2f 42 69 6e 6a 65 63 74 } //1 github.com/Binject
		$a_81_2 = {67 69 74 68 75 62 2e 63 6f 6d 2f 6b 65 6e 73 68 31 72 6f 2f 77 69 6c 6c 69 65 } //1 github.com/kensh1ro/willie
		$a_81_3 = {2e 6c 6f 63 61 6c 68 6f 73 74 2f 63 68 61 6e 6e 65 6c 73 } //1 .localhost/channels
		$a_81_4 = {49 6e 6a 65 63 74 69 6f 6e 48 61 6e 64 6c 65 72 2e 66 75 6e 63 32 } //1 InjectionHandler.func2
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}