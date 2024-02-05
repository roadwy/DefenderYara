
rule PWS_Win32_Lolyda_E{
	meta:
		description = "PWS:Win32/Lolyda.E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {10 8d 85 fc fe ff ff 50 e8 90 01 02 00 00 0b c0 0f 85 90 01 01 01 00 00 ff b5 e0 fe ff ff 6a 08 e8 90 01 02 00 00 89 85 a4 fc ff ff 0b c0 0f 84 90 09 04 00 68 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}