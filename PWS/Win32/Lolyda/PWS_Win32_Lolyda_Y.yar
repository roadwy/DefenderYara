
rule PWS_Win32_Lolyda_Y{
	meta:
		description = "PWS:Win32/Lolyda.Y,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 45 fc b0 e9 aa 8b 45 08 2b 45 fc 83 e8 05 ab } //01 00 
		$a_03_1 = {50 6a 0b 8d 85 90 01 02 ff ff 50 e8 90 01 04 58 0b c0 74 4e 90 00 } //01 00 
		$a_03_2 = {6a 00 6a 4a ff 75 fc e8 90 01 04 6a 10 90 01 1a 75 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}