
rule Trojan_Win32_Zbot_RN_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 45 f8 c8 db 00 00 8b 05 90 01 04 89 45 dc 8b 90 01 01 dc 89 90 01 01 e0 8b 90 01 01 e0 89 90 01 01 e4 8b 90 01 01 e4 89 90 01 01 e8 8b 90 01 01 08 8b 55 08 03 55 f0 8b 90 01 01 33 90 01 01 e8 03 90 01 01 f0 89 90 01 01 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}