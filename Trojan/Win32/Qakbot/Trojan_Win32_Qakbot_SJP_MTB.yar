
rule Trojan_Win32_Qakbot_SJP_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SJP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {40 30 8b 40 0c 66 3b c9 74 90 01 01 8b 40 90 01 01 8b 4d 90 01 01 eb 90 01 01 83 ec 90 01 01 bb 90 01 04 66 3b c0 74 90 01 01 3b 48 90 01 01 72 90 01 01 8b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}