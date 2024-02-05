
rule Trojan_Win32_Zbot_RH_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 8b 08 03 4d 10 8b 55 08 03 55 fc 66 89 0a 8b 45 f8 c1 e8 04 89 45 f8 8b 4d f8 83 e9 01 89 4d f8 } //00 00 
	condition:
		any of ($a_*)
 
}