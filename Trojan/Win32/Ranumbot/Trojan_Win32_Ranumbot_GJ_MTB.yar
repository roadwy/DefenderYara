
rule Trojan_Win32_Ranumbot_GJ_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {33 d6 33 ca 8d 90 01 01 24 90 01 01 89 90 01 01 24 90 01 01 e8 90 0a 64 00 8b 90 01 01 c1 90 01 01 05 c7 05 90 01 08 c7 05 90 01 04 ff ff ff ff 89 90 01 01 24 90 01 01 8b 90 01 01 24 90 01 01 01 90 01 01 24 90 01 01 81 3d 90 01 08 90 18 8b 90 01 01 24 90 01 01 8b 90 01 01 24 90 00 } //0a 00 
		$a_02_1 = {33 d6 33 ca 8d 90 01 01 24 90 01 01 e8 90 0a 64 00 8b 90 01 01 c1 90 01 01 05 c7 05 90 01 08 c7 05 90 01 04 ff ff ff ff 89 90 01 01 24 90 01 01 8b 90 01 01 24 90 01 01 01 90 01 01 24 90 01 01 81 3d 90 01 08 90 18 8b 90 01 01 24 90 01 01 8b 90 01 01 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}