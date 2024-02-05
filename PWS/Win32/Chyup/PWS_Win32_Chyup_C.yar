
rule PWS_Win32_Chyup_C{
	meta:
		description = "PWS:Win32/Chyup.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {80 7c 02 ff 7c 75 17 8b 45 fc e8 } //01 00 
		$a_03_1 = {89 3e 8b d6 83 c2 05 8b c3 e8 90 01 04 8b d6 83 c2 04 88 02 c6 03 e9 90 00 } //01 00 
		$a_01_2 = {66 ba d2 04 } //00 00 
	condition:
		any of ($a_*)
 
}