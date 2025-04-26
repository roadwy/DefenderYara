
rule Backdoor_Win32_Aptdrop_I_dha{
	meta:
		description = "Backdoor:Win32/Aptdrop.I!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {70 00 73 00 69 00 73 00 72 00 6e 00 64 00 72 00 78 00 2e 00 65 00 62 00 64 00 } //1 psisrndrx.ebd
		$a_00_1 = {47 3a 5c 57 6f 72 6b 5c 42 69 73 6f 6e 5c 42 69 73 6f 6e 4e 65 77 48 4e 53 74 75 62 44 6c 6c 5c 52 65 6c 65 61 73 65 5c 47 6f 6f 70 64 61 74 65 2e 70 64 62 } //1 G:\Work\Bison\BisonNewHNStubDll\Release\Goopdate.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}