
rule PWS_Win32_QQpass_BQ{
	meta:
		description = "PWS:Win32/QQpass.BQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 01 59 2b ca 8a d1 02 d0 30 10 40 8d 14 01 3b d6 72 } //01 00 
		$a_01_1 = {c6 07 e9 8b 47 01 89 45 fc 8d 0c 18 8b 45 08 8d 4c 01 05 89 4d f8 } //01 00 
		$a_01_2 = {c6 06 e8 2b c6 83 e8 05 89 46 01 8b 45 0c 83 f8 68 } //00 00 
	condition:
		any of ($a_*)
 
}