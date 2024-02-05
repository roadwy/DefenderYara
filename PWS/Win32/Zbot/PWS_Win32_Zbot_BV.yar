
rule PWS_Win32_Zbot_BV{
	meta:
		description = "PWS:Win32/Zbot.BV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 06 8b 45 c0 89 45 c8 8b 45 c8 83 38 00 74 5b 8b 45 c8 8b 00 25 00 00 00 80 74 14 8b 45 c8 0f b7 00 50 ff 75 bc ff 55 f4 } //01 00 
		$a_01_1 = {89 20 bf 23 00 00 00 8e df ff e0 } //00 00 
	condition:
		any of ($a_*)
 
}