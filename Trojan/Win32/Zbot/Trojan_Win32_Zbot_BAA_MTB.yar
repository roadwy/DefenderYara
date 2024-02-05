
rule Trojan_Win32_Zbot_BAA_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {50 8b 8d 68 dc ff ff 51 6a 00 ff 15 90 02 04 89 85 1c dc ff ff 6a 00 8d 95 40 dc ff ff 52 6a 0e 8d 85 44 dc ff ff 50 8b 8d 20 dc ff ff 51 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}