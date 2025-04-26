
rule PWS_Win32_Sinowal_gen_K{
	meta:
		description = "PWS:Win32/Sinowal.gen!K,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff 15 20 00 41 00 9c 50 66 a1 ?? ?? 40 00 } //1
		$a_03_1 = {68 18 10 40 00 9c 50 66 a1 ?? ?? 40 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}