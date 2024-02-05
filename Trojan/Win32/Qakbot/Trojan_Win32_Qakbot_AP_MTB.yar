
rule Trojan_Win32_Qakbot_AP_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 99 f7 7d e4 8b 45 10 0f b6 0c 10 8b 55 08 03 55 f8 0f b6 02 33 c1 8b 4d 08 03 4d f8 88 01 eb } //00 00 
	condition:
		any of ($a_*)
 
}