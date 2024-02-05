
rule PWS_Win32_Sinowal_gen_N{
	meta:
		description = "PWS:Win32/Sinowal.gen!N,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {ff ff 83 2c 02 ad 75 07 32 c0 e9 90 09 04 00 81 bd 90 00 } //01 00 
		$a_03_1 = {6a 18 8d 85 90 01 02 ff ff 50 6a 00 6a 00 68 00 00 07 00 8b 4d 08 51 ff 15 90 00 } //01 00 
		$a_03_2 = {3d a0 68 06 00 73 0d 68 f4 01 00 00 ff 15 90 01 04 eb c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}