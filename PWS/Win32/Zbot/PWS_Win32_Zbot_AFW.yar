
rule PWS_Win32_Zbot_AFW{
	meta:
		description = "PWS:Win32/Zbot.AFW,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 15 40 00 40 00 39 d0 75 02 eb d3 89 c7 81 f8 00 00 00 00 75 02 eb c7 89 c7 81 f8 00 00 00 00 75 02 eb bb } //00 00 
	condition:
		any of ($a_*)
 
}