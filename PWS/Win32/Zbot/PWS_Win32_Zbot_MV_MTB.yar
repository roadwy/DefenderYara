
rule PWS_Win32_Zbot_MV_MTB{
	meta:
		description = "PWS:Win32/Zbot.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 11 5d c3 90 0a 2e 00 8b ca a3 90 02 04 8b 90 02 05 31 90 02 05 a1 90 02 04 a3 90 02 04 8b 90 02 05 8b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}