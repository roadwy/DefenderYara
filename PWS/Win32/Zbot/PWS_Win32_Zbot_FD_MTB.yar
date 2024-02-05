
rule PWS_Win32_Zbot_FD_MTB{
	meta:
		description = "PWS:Win32/Zbot.FD!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 00 00 ff d0 eb 03 00 00 00 85 c0 } //00 00 
	condition:
		any of ($a_*)
 
}