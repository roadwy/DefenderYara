
rule Trojan_Win32_Qakbot_MP_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 55 fc 83 c2 01 89 55 fc 83 7d fc 12 73 28 8b 45 fc 6b c0 13 03 45 f8 50 8b 4d d0 51 8b 55 08 8b 82 44 03 00 00 ff d0 8b 4d fc 8b 55 08 } //00 00 
	condition:
		any of ($a_*)
 
}