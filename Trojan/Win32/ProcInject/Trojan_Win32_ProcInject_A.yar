
rule Trojan_Win32_ProcInject_A{
	meta:
		description = "Trojan:Win32/ProcInject.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 c1 8b 75 08 89 f7 ac 34 90 01 01 aa e2 fa 90 00 } //1
		$a_01_1 = {43 72 65 61 74 65 54 68 72 65 61 64 00 52 65 61 64 50 72 6f 63 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}