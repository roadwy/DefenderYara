
rule VirTool_Win32_VBInject_VY{
	meta:
		description = "VirTool:Win32/VBInject.VY,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {46 00 3a 00 5c 00 4c 00 65 00 21 00 54 00 6a 00 30 00 20 00 55 00 2e 00 64 00 5c 00 74 00 73 00 74 00 20 00 63 00 72 00 79 00 70 00 74 00 65 00 72 00 } //1 F:\Le!Tj0 U.d\tst crypter
		$a_01_1 = {5f 72 60 6a 65 63 74 31 } //1 _r`ject1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}