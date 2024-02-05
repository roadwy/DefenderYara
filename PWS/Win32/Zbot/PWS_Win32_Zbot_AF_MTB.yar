
rule PWS_Win32_Zbot_AF_MTB{
	meta:
		description = "PWS:Win32/Zbot.AF!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 06 8b c8 8b 0a 25 ff 00 00 00 81 e1 ff 00 00 00 3b c1 } //00 00 
	condition:
		any of ($a_*)
 
}