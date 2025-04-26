
rule PWS_Win32_QQpass_ED{
	meta:
		description = "PWS:Win32/QQpass.ED,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 65 74 20 6f 65 78 65 63 3d 57 73 68 65 6c 6c 2e 45 78 65 63 28 70 72 6f 67 72 61 6d 29 } //1 set oexec=Wshell.Exec(program)
		$a_01_1 = {2f 53 54 41 52 54 20 51 51 55 49 4e 3a 00 } //1 匯䅔呒儠啑义:
		$a_01_2 = {00 71 71 2e 73 63 72 00 } //1
		$a_01_3 = {00 26 71 71 70 61 73 73 77 6f 72 64 3d 00 } //1 ☀煱慰獳潷摲=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}