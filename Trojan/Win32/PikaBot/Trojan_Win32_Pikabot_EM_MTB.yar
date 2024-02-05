
rule Trojan_Win32_Pikabot_EM_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 06 00 "
		
	strings :
		$a_01_0 = {8a 84 0d 70 ff ff ff 34 e2 0f b6 c0 66 89 84 4d 44 fc ff ff 41 83 f9 26 7c e6 } //06 00 
		$a_01_1 = {0f af 47 40 89 47 40 8b 8e 88 00 00 00 8b 46 48 33 c1 2b 4e 10 2b 4e 24 48 01 46 34 } //06 00 
		$a_01_2 = {0f b6 84 0d 70 ff ff ff 66 83 e8 40 66 23 c3 66 89 84 4d 2c fc ff ff 41 83 f9 26 7c e3 } //00 00 
	condition:
		any of ($a_*)
 
}