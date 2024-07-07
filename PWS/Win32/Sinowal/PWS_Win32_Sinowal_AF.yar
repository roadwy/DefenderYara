
rule PWS_Win32_Sinowal_AF{
	meta:
		description = "PWS:Win32/Sinowal.AF,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {35 13 89 00 00 d1 e0 3d 26 12 01 00 75 } //5
		$a_01_1 = {00 70 64 62 2e 70 64 62 00 00 } //1
		$a_01_2 = {00 6f 2e 70 64 62 00 00 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}