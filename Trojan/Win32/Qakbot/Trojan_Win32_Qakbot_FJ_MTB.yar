
rule Trojan_Win32_Qakbot_FJ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.FJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 02 8b 45 c8 03 45 98 03 45 ec 03 45 a0 89 45 a8 6a 00 e8 90 01 04 8b 5d a8 2b d8 6a 00 e8 90 01 04 03 d8 8b 45 d8 31 18 83 45 ec 04 83 45 d8 04 8b 45 ec 3b 45 d4 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}