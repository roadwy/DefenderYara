
rule Ransom_Win32_DeleteShadows_A{
	meta:
		description = "Ransom:Win32/DeleteShadows.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 } //1 cmd.exe /c
		$a_00_1 = {76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 } //1 vssadmin.exe delete shadows /all /quiet
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}