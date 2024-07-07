
rule Trojan_Win32_Sergen_A{
	meta:
		description = "Trojan:Win32/Sergen.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 00 79 00 73 00 72 00 65 00 67 00 2e 00 65 00 78 00 65 00 } //1 sysreg.exe
		$a_01_1 = {69 00 6b 00 2e 00 50 00 6f 00 77 00 65 00 72 00 53 00 68 00 65 00 6c 00 6c 00 2e 00 50 00 53 00 32 00 45 00 58 00 45 00 48 00 6f 00 73 00 74 00 52 00 61 00 77 00 55 00 49 00 2e 00 53 00 65 00 74 00 42 00 75 00 66 00 66 00 65 00 72 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 73 00 } //1 ik.PowerShell.PS2EXEHostRawUI.SetBufferContents
		$a_01_2 = {50 00 53 00 32 00 45 00 58 00 45 00 5f 00 48 00 6f 00 73 00 74 00 } //1 PS2EXE_Host
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}