
rule PWS_Win32_Sinowal_gen_AE{
	meta:
		description = "PWS:Win32/Sinowal.gen!AE,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 81 57 e4 0a 90 09 03 00 44 44 44 90 00 } //1
		$a_01_1 = {81 57 e4 0a 44 44 44 44 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}