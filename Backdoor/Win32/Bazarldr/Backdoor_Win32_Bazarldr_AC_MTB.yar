
rule Backdoor_Win32_Bazarldr_AC_MTB{
	meta:
		description = "Backdoor:Win32/Bazarldr.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {0f b6 34 17 89 d1 31 d2 01 f3 89 d8 f7 f5 0f b6 04 17 89 d3 89 f2 88 04 0f 88 14 1f 31 d2 0f b6 04 0f 01 f0 f7 f5 0f b6 04 17 8b 54 24 ?? 30 02 8b 04 24 } //1
		$a_00_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_00_2 = {44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 } //1 DllGetClassObject
		$a_00_3 = {44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1 DllCanUnloadNow
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}