
rule Trojan_Win32_Qakbot_FV_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.FV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 5d a4 8b 45 ec 8b 55 d8 01 02 8b 45 c8 03 45 a4 8b 55 d8 31 02 83 45 ec 04 83 45 d8 04 8b 45 ec 3b 45 d4 72 } //00 00 
	condition:
		any of ($a_*)
 
}