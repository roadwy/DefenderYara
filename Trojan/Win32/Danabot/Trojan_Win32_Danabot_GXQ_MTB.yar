
rule Trojan_Win32_Danabot_GXQ_MTB{
	meta:
		description = "Trojan:Win32/Danabot.GXQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 33 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 29 45 90 01 01 8b 45 90 01 01 29 45 90 01 01 4b 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}