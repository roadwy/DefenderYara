
rule PWS_Win32_Sinowal_gen_J{
	meta:
		description = "PWS:Win32/Sinowal.gen!J,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 05 00 00 03 00 "
		
	strings :
		$a_03_0 = {ff 15 20 b0 40 00 90 90 ff 25 90 01 02 40 00 90 02 07 90 90 ff 25 90 00 } //03 00 
		$a_03_1 = {68 04 1b 40 00 90 90 ff 25 90 01 02 40 00 90 02 07 90 90 ff 25 90 00 } //03 00 
		$a_01_2 = {68 e7 be ad de } //02 00 
		$a_01_3 = {81 45 08 88 6a 3f 24 } //01 00 
		$a_01_4 = {81 3c 11 50 45 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}