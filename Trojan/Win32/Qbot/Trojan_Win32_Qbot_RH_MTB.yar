
rule Trojan_Win32_Qbot_RH_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {2b d8 8b 45 d8 33 18 89 5d a0 8b 45 d8 8b 55 a0 89 10 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_RH_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 88 c4 00 00 00 29 88 98 00 00 00 8b 88 fc 00 00 00 0f af da 8d 51 ff 33 d1 89 90 fc 00 00 00 8b 88 00 01 00 00 01 48 50 8b 88 ec 00 00 00 01 48 10 8b 90 80 00 00 00 8b 88 a8 00 00 00 88 1c 0a } //00 00 
	condition:
		any of ($a_*)
 
}