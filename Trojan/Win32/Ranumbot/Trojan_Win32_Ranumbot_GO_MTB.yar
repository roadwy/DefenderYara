
rule Trojan_Win32_Ranumbot_GO_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {c1 e9 05 c7 05 90 01 08 c7 05 90 01 04 ff ff ff ff 89 4d 90 01 01 8b 85 90 01 04 01 45 90 01 01 81 3d 90 01 08 90 18 8b 55 90 01 01 8b 4d 90 01 01 33 d6 33 ca 8d 85 90 01 04 e8 90 01 04 81 90 01 05 83 90 00 } //0a 00 
		$a_02_1 = {c1 e8 05 c7 05 90 01 08 c7 05 90 01 04 ff ff ff ff 89 4d 90 01 01 8b 85 90 01 04 01 45 90 01 01 81 3d 90 01 08 90 18 8b 55 90 01 01 8b 4d 90 01 01 33 d6 33 ca 8d 85 90 01 04 e8 90 01 04 81 90 01 05 83 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}