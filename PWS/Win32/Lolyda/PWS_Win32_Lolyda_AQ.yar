
rule PWS_Win32_Lolyda_AQ{
	meta:
		description = "PWS:Win32/Lolyda.AQ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {83 c0 07 a3 90 01 04 61 36 90 00 } //02 00 
		$a_01_1 = {61 3e 8b 89 c4 03 00 00 ff 25 } //01 00 
		$a_01_2 = {2b c6 83 e8 05 c6 06 e9 89 46 01 } //01 00 
		$a_01_3 = {83 c0 09 89 45 0c eb 03 8b 45 0c 8b 48 fc 2b 08 83 e9 05 } //00 00 
	condition:
		any of ($a_*)
 
}