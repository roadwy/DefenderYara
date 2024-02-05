
rule PWS_Win32_Sinowal_gen_K{
	meta:
		description = "PWS:Win32/Sinowal.gen!K,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff 15 20 00 41 00 9c 50 66 a1 90 01 02 40 00 90 00 } //01 00 
		$a_03_1 = {68 18 10 40 00 9c 50 66 a1 90 01 02 40 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}