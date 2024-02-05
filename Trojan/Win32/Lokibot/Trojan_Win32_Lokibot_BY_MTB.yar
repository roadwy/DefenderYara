
rule Trojan_Win32_Lokibot_BY_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 c4 f8 89 55 f8 89 45 fc 90 90 90 05 10 01 90 8b 5d fc ff 75 f8 01 1c 24 c3 90 00 } //01 00 
		$a_02_1 = {8b 45 f8 89 45 f0 90 90 90 05 10 01 90 68 90 01 01 00 00 00 e8 df 4b fa ff 90 90 90 05 10 01 90 83 fb 90 01 01 76 90 01 01 90 90 90 05 10 01 90 e8 de 4a fa ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}