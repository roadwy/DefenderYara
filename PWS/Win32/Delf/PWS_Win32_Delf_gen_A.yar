
rule PWS_Win32_Delf_gen_A{
	meta:
		description = "PWS:Win32/Delf.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,18 00 14 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {2e 55 70 61 63 6b } //06 00  .Upack
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //01 00  SOFTWARE\Borland\Delphi
		$a_00_2 = {53 6f 66 74 57 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SoftWare\Microsoft\Windows\CurrentVersion\Run
		$a_00_3 = {52 65 67 69 73 74 65 72 53 65 72 76 69 63 65 50 72 6f 63 65 73 73 } //01 00  RegisterServiceProcess
		$a_01_4 = {53 74 61 72 74 48 6f 6f 6b } //01 00  StartHook
		$a_00_5 = {69 66 20 65 78 69 73 74 20 22 } //01 00  if exist "
		$a_00_6 = {67 6f 74 6f 20 74 72 79 } //00 00  goto try
	condition:
		any of ($a_*)
 
}