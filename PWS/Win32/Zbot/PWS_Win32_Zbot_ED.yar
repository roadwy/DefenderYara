
rule PWS_Win32_Zbot_ED{
	meta:
		description = "PWS:Win32/Zbot.ED,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 04 68 00 30 00 00 a1 90 01 03 00 8b 40 50 50 a1 90 01 03 00 8b 40 34 50 a1 90 01 03 00 50 ff 15 90 01 03 00 a3 90 01 03 00 68 90 01 03 00 a1 90 01 03 00 8b 40 54 90 00 } //01 00 
		$a_00_1 = {83 ff 21 75 07 bf 01 00 00 00 eb 06 83 ff 21 74 01 47 } //00 00 
	condition:
		any of ($a_*)
 
}