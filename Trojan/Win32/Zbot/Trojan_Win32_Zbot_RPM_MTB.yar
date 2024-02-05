
rule Trojan_Win32_Zbot_RPM_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c0 e0 06 0a c2 8d 93 90 01 04 81 ca 90 01 04 88 84 3a 90 01 04 b8 90 01 04 33 d2 f7 f6 33 d2 bf 90 01 04 f7 f7 8a 45 90 01 01 8b fa 81 f7 90 01 04 3c e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}