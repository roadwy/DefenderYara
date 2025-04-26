
rule Trojan_Win32_Stealer_DAA_MTB{
	meta:
		description = "Trojan:Win32/Stealer.DAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_81_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
		$a_81_2 = {2f 63 20 63 64 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 20 26 20 63 75 72 6c 20 2d 6f } //1 /c cd C:\Windows\Temp\ & curl -o
		$a_81_3 = {63 6d 64 2e 65 78 65 } //1 cmd.exe
		$a_81_4 = {26 20 73 74 61 72 74 } //1 & start
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}