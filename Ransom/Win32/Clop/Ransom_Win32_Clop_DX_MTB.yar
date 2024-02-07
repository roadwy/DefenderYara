
rule Ransom_Win32_Clop_DX_MTB{
	meta:
		description = "Ransom:Win32/Clop.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {2f 43 20 76 73 73 61 64 6d 69 6e 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //01 00  /C vssadmin Delete Shadows /all /quiet
		$a_81_1 = {2f 43 20 6e 65 74 20 73 74 6f 70 20 42 61 63 6b 75 70 45 78 65 63 56 53 53 50 72 6f 76 69 64 65 72 20 2f 79 } //01 00  /C net stop BackupExecVSSProvider /y
		$a_81_2 = {52 45 41 44 4d 45 5f 52 45 41 44 4d 45 2e 74 78 74 } //01 00  README_README.txt
		$a_81_3 = {2d 2d 2d 2d 2d 42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d } //01 00  -----BEGIN PUBLIC KEY-----
		$a_81_4 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //00 00  CreateToolhelp32Snapshot
	condition:
		any of ($a_*)
 
}