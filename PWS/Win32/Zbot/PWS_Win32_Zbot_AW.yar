
rule PWS_Win32_Zbot_AW{
	meta:
		description = "PWS:Win32/Zbot.AW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {00 fe 00 40 3b c3 75 f9 46 81 fe 90 01 03 00 75 e6 33 f6 cf 90 09 0b 00 33 f6 b8 90 01 03 00 bb 90 00 } //01 00 
		$a_02_1 = {4d 5a 00 00 90 01 04 62 74 6e 31 00 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}