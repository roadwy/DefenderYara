
rule PWS_Win32_Tibia_BJ{
	meta:
		description = "PWS:Win32/Tibia.BJ,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {3a 74 74 69 62 69 61 2e 3a 31 28 } //01 00  :ttibia.:1(
		$a_00_1 = {61 63 63 6f 75 6e 74 5f 6e 61 6d 65 } //01 00  account_name
		$a_00_2 = {61 63 63 6f 75 6e 74 5f 70 61 73 73 77 6f 72 64 } //02 00  account_password
		$a_03_3 = {53 6a 00 6a 09 e8 90 01 04 50 e8 90 01 04 a3 90 01 04 83 3d 90 01 04 00 0f 95 c3 84 db 74 90 01 01 68 90 01 04 a1 90 01 04 50 e8 90 01 04 a1 c0 22 4b 00 50 6a 00 68 ff 0f 1f 00 e8 90 01 04 a3 90 01 04 e8 90 01 04 8b c3 5b c3 90 00 } //02 00 
		$a_03_4 = {ba 03 00 00 00 e8 90 01 04 8d 45 fc ba 90 01 04 e8 90 01 04 8b 45 fc 80 38 30 75 90 01 01 6a 0a e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}