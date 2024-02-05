
rule Trojan_Win32_Spambot_B{
	meta:
		description = "Trojan:Win32/Spambot.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 57 56 53 90 02 30 31 db 66 90 90 c7 04 24 90 01 04 0f b6 b3 90 01 04 e8 90 01 04 31 d2 89 c1 89 d8 f7 f1 89 f0 83 c3 01 83 ec 04 32 82 90 01 04 88 83 90 01 04 81 fb 90 01 04 75 c9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}