
rule Backdoor_Win32_Farfli_BX_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.BX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {8d 55 e8 b1 cc 03 d0 2a c8 40 32 0a 88 0c 13 83 f8 05 76 } //3
		$a_01_1 = {43 3a 5c 73 79 73 6c 6f 67 2e 64 61 74 } //2 C:\syslog.dat
		$a_01_2 = {43 63 4d 61 69 6e 44 6c 6c 2e 64 6c 6c } //2 CcMainDll.dll
		$a_01_3 = {54 65 73 74 46 75 6e } //1 TestFun
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=8
 
}