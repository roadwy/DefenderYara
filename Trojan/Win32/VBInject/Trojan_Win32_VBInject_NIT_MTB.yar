
rule Trojan_Win32_VBInject_NIT_MTB{
	meta:
		description = "Trojan:Win32/VBInject.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 ce 00 10 40 00 [0-30] ad [0-30] bb 54 8b ec 83 [0-30] 43 [0-30] 39 18 [0-30] 75 [0-30] bb eb 0c 56 8d [0-30] 39 58 04 [0-30] 75 } //2
		$a_01_1 = {56 42 41 36 2e 44 4c 4c } //1 VBA6.DLL
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}