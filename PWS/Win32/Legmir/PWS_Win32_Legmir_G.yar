
rule PWS_Win32_Legmir_G{
	meta:
		description = "PWS:Win32/Legmir.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {9b 83 83 83 80 c2 88 8d 98 d7 9b 83 83 83 80 d4 d4 c2 88 8d 98 d7 81 85 9e dd c2 88 8d 98 d7 ec 5e 7c 87 77 } //01 00 
		$a_01_1 = {9b 83 83 83 80 c2 89 94 89 d7 81 85 9e c2 89 94 89 d7 ec 83 e5 4f } //01 00 
		$a_01_2 = {64 6c 6c 2e 64 6c 6c 00 57 53 50 53 74 61 72 74 75 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}