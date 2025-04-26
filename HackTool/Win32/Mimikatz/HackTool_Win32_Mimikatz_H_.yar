
rule HackTool_Win32_Mimikatz_H_{
	meta:
		description = "HackTool:Win32/Mimikatz.H!!Mikatz.gen!F,SIGNATURE_TYPE_ARHSTR_EXT,08 00 08 00 0a 00 00 "
		
	strings :
		$a_80_0 = {6c 6f 67 20 6d 69 6d 69 6b 61 74 7a 20 69 6e 70 75 74 2f 6f 75 74 70 75 74 20 74 6f 20 66 69 6c 65 } //log mimikatz input/output to file  2
		$a_80_1 = {2f 6d 69 6d 69 6b 61 74 7a } ///mimikatz  2
		$a_80_2 = {67 65 6e 74 69 6c 6b 69 77 69 } //gentilkiwi  2
		$a_80_3 = {5c 5c 2e 5c 70 69 70 65 5c 6b 65 6b 65 6f 5f 74 73 73 73 70 5f 65 6e 64 70 6f 69 6e 74 } //\\.\pipe\kekeo_tsssp_endpoint  2
		$a_80_4 = {6c 73 61 63 61 6c 6c 61 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 70 61 63 6b 61 67 65 } //lsacallauthenticationpackage  1
		$a_80_5 = {73 61 6d 65 6e 75 6d 65 72 61 74 65 75 73 65 72 73 69 6e 64 6f 6d 61 69 6e } //samenumerateusersindomain  1
		$a_80_6 = {6c 73 61 6c 6f 6f 6b 75 70 61 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 70 61 63 6b 61 67 65 } //lsalookupauthenticationpackage  1
		$a_80_7 = {73 6f 66 74 77 61 72 65 5c 70 6f 6c 69 63 69 65 73 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 72 65 64 65 6e 74 69 61 6c 73 64 65 6c 65 67 61 74 69 6f 6e } //software\policies\microsoft\windows\credentialsdelegation  1
		$a_80_8 = {73 79 73 74 65 6d 5c 63 75 72 72 65 6e 74 63 6f 6e 74 72 6f 6c 73 65 74 5c 63 6f 6e 74 72 6f 6c 5c 6c 73 61 5c 63 72 65 64 73 73 70 5c 70 6f 6c 69 63 79 64 65 66 61 75 6c 74 73 } //system\currentcontrolset\control\lsa\credssp\policydefaults  1
		$a_80_9 = {61 63 71 75 69 72 65 63 72 65 64 65 6e 74 69 61 6c 73 68 61 6e 64 6c 65 3a } //acquirecredentialshandle:  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=8
 
}