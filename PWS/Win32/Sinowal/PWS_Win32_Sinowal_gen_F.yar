
rule PWS_Win32_Sinowal_gen_F{
	meta:
		description = "PWS:Win32/Sinowal.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 ac 38 40 00 ff 25 78 11 40 00 90 02 07 ff 25 90 00 } //01 00 
		$a_02_1 = {c6 00 01 ff 25 64 11 40 00 90 02 07 ff 25 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}