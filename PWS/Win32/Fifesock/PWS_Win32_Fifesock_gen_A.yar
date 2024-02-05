
rule PWS_Win32_Fifesock_gen_A{
	meta:
		description = "PWS:Win32/Fifesock.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6e 73 70 72 c7 45 90 01 01 34 2e 64 6c 66 c7 45 90 01 01 6c 00 c7 45 90 01 01 77 73 32 5f c7 45 90 01 01 33 32 2e 64 66 c7 45 90 01 01 6c 6c c6 45 90 01 01 00 c7 45 90 01 01 77 69 6e 69 90 00 } //01 00 
		$a_03_1 = {6a 40 68 00 30 00 00 90 01 02 05 90 01 01 6a 00 ff 15 90 02 0c 51 50 89 86 90 01 01 00 00 00 e8 90 01 04 8b 90 01 02 00 00 00 90 02 03 c6 90 01 02 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}