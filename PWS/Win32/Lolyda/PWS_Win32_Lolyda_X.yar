
rule PWS_Win32_Lolyda_X{
	meta:
		description = "PWS:Win32/Lolyda.X,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b d8 83 e3 05 83 fb 05 75 90 01 01 83 c0 03 89 45 f8 90 00 } //01 00 
		$a_03_1 = {8b d8 83 e3 09 83 fb 09 75 90 01 01 83 c0 25 89 45 f0 8b 45 f0 90 00 } //02 00 
		$a_01_2 = {83 fb 47 72 30 83 fb 49 76 22 83 fb 4a 76 26 83 fb 4d 76 15 83 fb 4e 76 1c 83 fb 51 76 08 83 fb 52 75 12 } //00 00 
	condition:
		any of ($a_*)
 
}