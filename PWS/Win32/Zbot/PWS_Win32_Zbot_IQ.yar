
rule PWS_Win32_Zbot_IQ{
	meta:
		description = "PWS:Win32/Zbot.IQ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 8b 1f 66 83 c3 90 01 01 66 89 1f 66 83 07 90 01 01 6a 90 01 01 58 39 d0 47 83 c7 01 81 c3 90 01 02 40 00 74 08 4e 42 f7 c0 90 01 02 40 00 50 c7 04 24 90 01 02 40 00 5a 39 fa 75 a3 81 f6 90 01 02 40 00 74 08 01 d8 81 ee 90 01 02 40 00 41 68 90 01 03 00 8b 14 24 58 3b d1 0f 85 58 ff ff ff 89 d2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}