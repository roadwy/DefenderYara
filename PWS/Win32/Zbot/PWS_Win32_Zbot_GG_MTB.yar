
rule PWS_Win32_Zbot_GG_MTB{
	meta:
		description = "PWS:Win32/Zbot.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {99 f7 f9 f7 da 1b d2 f7 da f7 da 66 89 90 02 05 c7 85 90 02 fa 66 8b f0 8d 85 90 02 04 50 8d 90 02 02 50 e8 90 02 04 50 e8 90 02 04 66 33 f0 0f bf c6 50 8d 85 90 02 04 50 e8 90 02 04 8d 85 90 02 04 50 8d 85 90 02 04 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}