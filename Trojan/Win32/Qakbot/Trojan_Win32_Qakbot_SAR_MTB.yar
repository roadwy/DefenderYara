
rule Trojan_Win32_Qakbot_SAR_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 08 8b 45 90 01 01 66 90 01 02 74 90 01 01 83 e8 90 01 01 8b 4d 90 01 01 83 d9 90 01 01 eb 90 01 01 40 89 45 90 01 01 8b 45 90 01 01 3a db 74 90 00 } //01 00 
		$a_03_1 = {0f b6 08 66 90 01 02 74 90 01 01 8b 45 90 01 01 0f b6 44 10 90 01 01 33 c8 3a c0 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}