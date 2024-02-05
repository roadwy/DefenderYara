
rule PWS_Win32_Sinowal_gen_L{
	meta:
		description = "PWS:Win32/Sinowal.gen!L,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {9d 5d 9c 50 66 } //01 00 
		$a_02_1 = {66 a9 01 28 58 0f 85 90 01 04 9d 0f 90 00 } //01 00 
		$a_00_2 = {4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 } //00 00 
	condition:
		any of ($a_*)
 
}