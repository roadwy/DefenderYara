
rule PWS_Win32_Sinowal_gen_G{
	meta:
		description = "PWS:Win32/Sinowal.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 20 a0 40 00 ff 25 f4 10 40 00 90 02 07 ff 25 90 00 } //01 00 
		$a_02_1 = {ff 15 14 a0 40 00 ff 25 f0 10 40 00 90 02 07 ff 25 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}