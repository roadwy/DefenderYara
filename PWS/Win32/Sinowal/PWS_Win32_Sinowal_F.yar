
rule PWS_Win32_Sinowal_F{
	meta:
		description = "PWS:Win32/Sinowal.F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 01 45 fc 8b 06 8b 7d f4 33 c7 90 02 0c 83 f9 00 90 02 06 0f 84 90 00 } //01 00 
		$a_03_1 = {8b 45 c4 83 c0 01 89 45 c4 90 02 03 e9 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}