
rule Trojan_Win32_Qbot_A_{
	meta:
		description = "Trojan:Win32/Qbot.A!!Qbot.A,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b cb 89 4d fc 90 0a 25 00 90 03 04 04 6a 5a 33 d2 33 d2 6a 5a 8b c1 5e f7 f6 8b 45 90 01 01 8a 04 02 90 02 03 32 04 90 01 01 74 08 41 3b 4d 90 01 01 72 90 00 } //01 00 
		$a_03_1 = {5f 5e 5b c9 c3 90 0a 2a 00 8b 4d 90 01 01 8b 45 90 01 01 03 ce 03 c1 33 d2 6a 5a 5b f7 f3 8b 45 90 01 01 8a 04 02 32 04 37 46 88 01 3b 75 fc 72 de 8b 45 90 00 } //0a 00 
	condition:
		any of ($a_*)
 
}