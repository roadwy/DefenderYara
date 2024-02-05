
rule PWS_Win32_Zbot_AP{
	meta:
		description = "PWS:Win32/Zbot.AP,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {88 18 90 90 40 50 58 3d ff 21 41 00 90 90 90 75 e6 50 58 61 90 90 90 68 5f 20 41 00 50 58 c3 00 00 00 00 00 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}