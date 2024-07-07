
rule PWS_Win32_Populf_E_dll{
	meta:
		description = "PWS:Win32/Populf.E!dll,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 12 6a 00 68 60 f0 00 00 68 12 01 00 00 50 e8 90 01 04 6a 00 68 90 01 04 e8 90 01 04 85 c0 74 12 6a 00 68 60 f0 00 00 68 12 01 00 00 50 e8 90 01 04 6a 00 68 90 01 04 e8 90 01 04 85 c0 74 0d 90 00 } //1
		$a_03_1 = {66 3d 01 80 0f 85 90 01 02 00 00 33 c0 8a c3 83 c0 f8 3d d6 00 00 00 0f 87 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}