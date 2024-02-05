
rule PWS_Win32_Quopax_A_dll{
	meta:
		description = "PWS:Win32/Quopax.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 02 6a 00 68 00 fc ff ff 56 ff 15 90 01 03 10 68 00 04 00 00 e8 90 01 03 00 83 c4 04 8b f8 8d 44 24 08 6a 00 50 68 00 04 00 00 90 00 } //01 00 
		$a_03_1 = {68 b8 0b 00 00 ff d7 8d 85 90 01 02 ff ff 50 ff d3 85 c0 75 90 01 01 46 83 fe 19 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}