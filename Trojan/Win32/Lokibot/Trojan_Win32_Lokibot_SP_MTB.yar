
rule Trojan_Win32_Lokibot_SP_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {5d c2 08 00 90 0a 50 00 55 8b ec 90 05 10 01 90 eb 90 01 01 90 05 10 01 90 8a 45 08 90 05 10 01 90 30 90 01 01 90 05 10 01 90 eb 90 01 01 90 05 10 01 90 8b 90 01 01 0c 90 05 10 01 90 eb 90 01 01 90 05 10 01 90 5d c2 08 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}