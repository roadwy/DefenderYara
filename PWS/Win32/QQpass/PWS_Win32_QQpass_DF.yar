
rule PWS_Win32_QQpass_DF{
	meta:
		description = "PWS:Win32/QQpass.DF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6a 6f 62 79 6c 69 76 65 32 2e 77 32 32 2e 68 61 6f 68 61 6f 68 6f 73 74 2e 63 6e 2f 63 2f 61 62 62 78 2f 71 71 70 6f 73 74 2e 61 73 70 } //01 00 
		$a_01_1 = {5c 59 6c 64 71 71 2e 64 6c 6c 00 5c 51 51 2e 65 78 65 00 26 71 71 70 61 73 73 77 6f 72 64 3d 00 3f 71 71 6e 75 6d 62 65 72 3d } //00 00 
	condition:
		any of ($a_*)
 
}