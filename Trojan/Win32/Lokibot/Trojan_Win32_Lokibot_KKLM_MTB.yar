
rule Trojan_Win32_Lokibot_KKLM_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.KKLM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 50 a4 4c f8 fa bb 35 c3 7c ad 34 95 a5 2c e5 3d fe f2 04 0f 40 d1 62 b6 95 7e e4 } //00 00 
	condition:
		any of ($a_*)
 
}