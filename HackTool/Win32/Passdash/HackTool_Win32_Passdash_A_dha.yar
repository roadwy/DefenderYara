
rule HackTool_Win32_Passdash_A_dha{
	meta:
		description = "HackTool:Win32/Passdash.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b cd 2b 4f 34 8d 86 a0 00 00 00 51 55 e8 ?? ?? ?? ?? 8d 7e 28 8d 54 24 ?? 8b cb c7 44 24 ?? 00 00 00 00 e8 } //2
		$a_01_1 = {43 68 61 6e 67 69 6e 67 20 4e 54 4c 4d 20 63 72 65 64 65 6e 74 69 61 6c 73 20 6f 66 20 6c 6f 67 6f 6e 20 73 65 73 73 69 6f 6e } //2 Changing NTLM credentials of logon session
		$a_01_2 = {4c 55 49 44 3a 55 73 65 72 4e 61 6d 65 3a 4c 6f 67 6f 6e 44 6f 6d 61 69 6e 3a 4c 4d 68 61 73 68 3a 4e 54 68 61 73 68 } //1 LUID:UserName:LogonDomain:LMhash:NThash
		$a_01_3 = {2d 64 62 67 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}