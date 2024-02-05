
rule Trojan_Win32_Lokibot_CY_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.CY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 c4 f8 89 55 f8 89 45 fc 90 90 90 05 10 01 90 8b 90 01 01 fc ff 75 f8 01 90 01 01 24 c3 90 00 } //01 00 
		$a_02_1 = {fa ff 8b d8 90 90 90 05 10 01 90 85 db 74 90 01 01 90 90 90 05 10 01 90 90 02 08 90 90 90 05 10 01 90 ba 90 01 04 8b c3 e8 90 01 02 fa ff 90 90 90 05 10 01 90 8b c3 e8 90 01 02 fa ff 90 90 90 05 15 01 90 90 02 06 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}