
rule Trojan_Win32_Qbot_PDSK_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PDSK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 54 24 2b 8a 74 24 2b 8b 74 24 0c 8a 1c 06 30 f2 88 54 24 2b 8b 44 24 08 88 1c 08 } //02 00 
		$a_01_1 = {8a 1c 16 01 c9 88 c7 0f b6 c7 8b 74 24 08 8a 3c 06 89 4c 24 50 30 df 8b 44 24 0c 88 3c 10 } //00 00 
	condition:
		any of ($a_*)
 
}