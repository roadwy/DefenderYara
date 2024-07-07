
rule PWS_Win32_Gaewe_A{
	meta:
		description = "PWS:Win32/Gaewe.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 73 74 61 72 74 5c 44 4e 46 43 6f 6d 70 6f 6e 65 6e 74 2e 44 4c 4c 00 } //1
		$a_00_1 = {63 6f 6d 6d 64 6c 6c 2e 64 6c 6c } //1 commdll.dll
		$a_03_2 = {68 a0 86 01 00 e8 90 01 04 6a 00 8d 55 f8 33 c0 e8 90 01 04 8b 45 f8 e8 90 01 04 50 e8 90 01 04 e8 90 01 04 33 c0 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}