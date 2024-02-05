
rule Trojan_Win32_Danabot_MTB{
	meta:
		description = "Trojan:Win32/Danabot!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 45 fc 8d 34 03 e8 90 01 04 30 06 b8 01 00 00 00 29 45 fc 39 7d fc 7d 90 00 } //02 00 
		$a_02_1 = {30 04 3e b8 01 00 00 00 29 85 f4 f7 ff ff 8b b5 f4 f7 ff ff 3b f3 7d 90 09 05 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}