
rule Trojan_Win32_Lokibot_AP_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 04 0a 01 f3 0f 6e c0 0f 6e 0b 0f ef c1 90 02 10 51 0f 7e c1 88 c8 59 90 02 10 29 f3 83 c3 01 75 90 00 } //01 00 
		$a_03_1 = {31 db 66 31 0c 18 81 fb 90 01 02 00 00 7d 90 01 01 83 c3 02 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}