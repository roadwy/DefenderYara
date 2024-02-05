
rule Trojan_Win32_Spambot_SMC_MTB{
	meta:
		description = "Trojan:Win32/Spambot.SMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 74 08 90 01 01 8d 14 16 81 e2 90 01 04 8a 5c 10 90 1b 00 88 5c 08 90 1b 00 8b de 88 5c 10 90 1b 00 33 db 8a 5c 08 90 1b 00 03 f3 81 e6 90 1b 01 8b 5d 90 01 01 8b 7d 90 01 01 8a 1c 3b 32 5c 30 90 1b 00 8b 75 90 01 01 8b 7d 90 1b 08 88 1c 3e 90 00 } //01 00 
		$a_02_1 = {33 d2 f7 f1 03 d7 8a 02 88 84 1d 90 01 03 ff 83 c3 90 01 01 81 fb 90 01 04 0f 82 90 0a 27 00 8b c3 04 90 01 01 88 44 1e 90 01 01 8d 43 90 1b 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}