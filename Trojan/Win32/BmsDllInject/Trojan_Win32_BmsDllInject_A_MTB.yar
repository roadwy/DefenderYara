
rule Trojan_Win32_BmsDllInject_A_MTB{
	meta:
		description = "Trojan:Win32/BmsDllInject.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {5c 52 65 6c 65 61 73 65 5c 78 36 34 5c 52 75 6e 52 65 73 45 78 65 2e 70 64 62 } //1 \Release\x64\RunResExe.pdb
		$a_81_1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 4e 6f 50 20 2d 4e 6f 6e 49 20 2d 57 20 48 69 64 64 65 6e 20 2d 65 70 20 42 79 70 61 73 73 20 2d 65 6e 63 20 63 77 42 6a 41 47 67 41 64 41 42 68 41 48 4d 41 61 77 42 7a 41 43 41 41 4c 77 42 6a 41 48 49 41 5a 51 42 68 41 48 51 41 5a 51 41 67 41 43 38 41 63 67 42 31 41 43 41 41 } //1 powershell.exe -NoP -NonI -W Hidden -ep Bypass -enc cwBjAGgAdABhAHMAawBzACAALwBjAHIAZQBhAHQAZQAgAC8AcgB1ACAA
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}