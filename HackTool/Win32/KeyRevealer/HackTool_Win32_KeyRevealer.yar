
rule HackTool_Win32_KeyRevealer{
	meta:
		description = "HackTool:Win32/KeyRevealer,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {43 72 79 70 74 47 65 6e 4b 65 79 } //CryptGenKey  01 00 
		$a_80_1 = {43 72 79 70 74 45 78 70 6f 72 74 4b 65 79 } //CryptExportKey  01 00 
		$a_80_2 = {5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 72 6b 66 72 65 65 5c 72 6b 66 72 65 65 2e 65 78 65 } //\Program Files\rkfree\rkfree.exe  01 00 
		$a_80_3 = {52 65 76 65 61 6c 65 72 20 4b 65 79 6c 6f 67 67 65 72 20 46 72 65 65 } //Revealer Keylogger Free  01 00 
		$a_80_4 = {72 76 6c 6b 6c 5c 63 66 67 5c 63 66 67 } //rvlkl\cfg\cfg  01 00 
		$a_80_5 = {52 56 4c 4b 4c 53 65 74 75 70 46 69 6c 65 4d 61 70 70 69 6e 67 } //RVLKLSetupFileMapping  01 00 
		$a_80_6 = {53 65 54 61 6b 65 4f 77 6e 65 72 73 68 69 70 50 72 69 76 69 6c 65 67 65 } //SeTakeOwnershipPrivilege  00 00 
	condition:
		any of ($a_*)
 
}