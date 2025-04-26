
rule Trojan_Win32_DelfInject_QA_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.QA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {48 54 54 50 57 65 62 4e 6f 64 65 2e 41 67 65 6e 74 } //3 HTTPWebNode.Agent
		$a_81_1 = {42 6f 72 6c 61 6e 64 20 53 4f 41 50 20 31 2e 32 } //3 Borland SOAP 1.2
		$a_81_2 = {53 4f 41 50 41 74 74 61 63 68 } //3 SOAPAttach
		$a_81_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 57 } //3 ShellExecuteExW
		$a_81_4 = {49 6e 74 65 72 6e 65 74 43 72 61 63 6b 55 72 6c 41 } //3 InternetCrackUrlA
		$a_81_5 = {62 61 73 65 36 34 42 69 6e 61 72 79 } //3 base64Binary
		$a_81_6 = {43 65 61 45 75 73 59 4e 62 72 4a } //3 CeaEusYNbrJ
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}