
rule PWS_Win32_Sinowal_gen_T{
	meta:
		description = "PWS:Win32/Sinowal.gen!T,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {68 80 a1 40 00 68 80 a1 40 00 } //1
		$a_02_1 = {8b 45 bc 83 c0 01 89 45 bc 83 7d bc 90 01 01 0f 90 00 } //1
		$a_00_2 = {8b c0 55 8b ec 83 ec 28 6a 20 6a 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}