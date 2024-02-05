
rule PWS_Win32_Zbot_OV{
	meta:
		description = "PWS:Win32/Zbot.OV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 89 e5 83 ec 08 bf 02 00 00 00 ba 00 20 40 00 47 30 12 f7 d2 f7 da 81 fa 00 c2 41 00 75 } //00 00 
	condition:
		any of ($a_*)
 
}