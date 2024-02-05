
rule PWS_Win32_Fareit_gen_C{
	meta:
		description = "PWS:Win32/Fareit.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 d8 1b ff 68 90 01 03 00 81 e7 00 00 04 00 ff d6 f7 d8 1b f6 33 db 53 81 e6 90 01 03 00 56 57 ff 15 90 01 03 00 89 45 fc 8d 45 f4 50 89 5d f4 89 5d f8 ff 15 90 01 03 00 8b 7d f8 0b 7d f4 56 f7 df 1b ff 53 ff 75 fc 81 e7 90 02 0a ff 15 90 01 03 00 8b f0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}