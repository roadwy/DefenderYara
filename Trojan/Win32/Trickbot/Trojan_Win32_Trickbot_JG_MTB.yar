
rule Trojan_Win32_Trickbot_JG_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.JG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {5f 5e 5d 5b 90 0a 60 00 8b 74 90 02 05 81 90 01 01 ff 90 01 03 0f b6 90 01 03 03 90 01 01 81 90 01 01 ff 90 01 03 0f b6 90 01 03 88 44 90 01 02 02 90 01 01 0f b6 90 01 01 88 54 90 01 02 8a 54 90 01 02 30 90 02 05 3b 90 01 01 7c 90 00 } //01 00 
		$a_02_1 = {41 3b cd 7c 90 01 01 5f 5e 90 0a 64 00 7e 90 01 01 8b 9c 90 01 05 8b 7c 90 01 02 8b 74 90 01 02 46 81 e6 90 01 04 0f b6 90 01 03 03 90 01 01 81 e7 90 01 04 0f b6 90 01 03 88 44 90 01 02 02 90 01 01 0f b6 90 01 01 88 54 90 01 02 8a 54 90 01 02 30 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}