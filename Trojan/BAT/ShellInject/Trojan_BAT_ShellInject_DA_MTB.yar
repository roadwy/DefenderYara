
rule Trojan_BAT_ShellInject_DA_MTB{
	meta:
		description = "Trojan:BAT/ShellInject.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 06 00 00 "
		
	strings :
		$a_81_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } //10 powershell.exe
		$a_81_1 = {73 68 65 6c 6c 63 6f 64 65 } //10 shellcode
		$a_81_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 52 65 70 6c 61 63 65 28 } //10 CreateObject(Replace(
		$a_81_3 = {72 65 67 20 61 64 64 20 22 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 5c 2e 70 77 6e 5c 53 68 65 6c 6c 5c 4f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //10 reg add "HKCU\Software\Classes\.pwn\Shell\Open\command
		$a_81_4 = {61 2a 6d 2a 73 2a 69 2e 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 64 6c 2a 2a 2a 2a 2a 2a 6c 2a } //1 a*m*s*i.*********************dl******l*
		$a_81_5 = {41 2a 2a 6d 2a 73 69 53 2a 2a 63 2a 61 2a 2a 2a 2a 2a 2a 2a 6e 2a 42 75 66 2a 66 2a 65 72 } //1 A**m*siS**c*a*******n*Buf*f*er
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*10+(#a_81_3  & 1)*10+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=41
 
}