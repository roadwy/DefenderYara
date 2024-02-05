
rule Trojan_Win32_Qakbot_SJO_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SJO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 f6 8b 45 90 01 01 eb 90 01 01 e8 90 01 04 bb 90 01 04 66 3b c9 74 90 01 01 53 5e 66 3b f6 74 90 01 01 0f b6 44 10 90 01 01 33 c8 e9 90 01 04 33 d2 bb 90 01 04 66 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}