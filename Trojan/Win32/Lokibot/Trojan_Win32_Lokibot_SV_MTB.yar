
rule Trojan_Win32_Lokibot_SV_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.SV!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 45 f9 32 45 fb 88 01 83 e8 00 83 e8 00 83 e8 00 83 e8 00 8a 55 fa 8b c1 e8 ec fe ff ff eb 05 8a 45 f9 88 01 43 4e 75 95 } //01 00 
		$a_01_1 = {8b c8 83 e8 00 30 11 83 e8 00 } //00 00 
	condition:
		any of ($a_*)
 
}