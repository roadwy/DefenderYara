
rule Trojan_Win32_Qakbot_PX_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 3a c0 90 13 bb 08 00 00 00 53 66 3b f6 90 13 5e f7 f6 66 3b c0 90 13 8b 45 90 01 01 0f b6 44 10 90 01 01 66 3b c0 90 13 33 c8 8b 45 90 01 01 3a db 90 13 03 45 90 01 01 88 08 90 13 8b 45 90 01 01 40 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}