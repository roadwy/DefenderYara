
rule Worm_Win32_Vexral_A{
	meta:
		description = "Worm:Win32/Vexral.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {6a 40 68 00 30 00 00 ff 76 50 ff 76 34 ff 75 90 01 01 ff 90 02 02 3b c3 90 00 } //01 00 
		$a_00_1 = {23 42 4f 54 23 55 52 4c 44 6f 77 6e 6c 6f 61 64 } //01 00  #BOT#URLDownload
		$a_02_2 = {66 61 63 65 62 6f 6f 6b 2e 90 02 04 2f 61 6a 61 78 2f 63 68 61 74 2f 73 65 6e 64 2e 70 68 70 90 00 } //01 00 
		$a_00_3 = {6c 6f 67 69 6e 5f 70 61 73 73 77 6f 72 64 3d } //01 00  login_password=
		$a_00_4 = {47 54 61 6c 6b 20 49 6e 73 74 61 6e 74 20 4d 65 73 73 61 67 65 } //00 00  GTalk Instant Message
	condition:
		any of ($a_*)
 
}