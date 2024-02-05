
rule Trojan_Win32_Lokibot_TS_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.TS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec 8b 4d 0c 90 05 10 01 90 8a 45 08 90 05 10 01 90 30 90 01 01 90 05 10 01 90 5d c2 90 00 } //01 00 
		$a_03_1 = {5f 5e 5b c3 90 0a 70 00 6a 00 68 90 01 04 e8 90 01 04 90 05 10 01 90 83 fb 90 01 01 90 05 10 01 90 7e 90 01 01 90 05 10 01 90 c7 05 90 01 08 90 05 10 01 90 90 02 02 e8 90 01 04 90 05 10 01 90 eb 90 01 01 90 05 10 01 90 4e 75 90 01 08 90 05 10 01 90 5f 5e 5b c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}