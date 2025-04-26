
rule Trojan_Win32_VBInject_BAD_MTB{
	meta:
		description = "Trojan:Win32/VBInject.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {b9 0c fe 19 5b 01 cb fe 48 a8 30 d9 47 15 7a 9d cc 43 72 } //3
		$a_01_1 = {25 66 f1 46 90 35 be f4 5a 4c 08 91 e7 e0 ee 57 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}