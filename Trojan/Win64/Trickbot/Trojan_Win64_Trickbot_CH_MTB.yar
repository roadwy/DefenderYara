
rule Trojan_Win64_Trickbot_CH_MTB{
	meta:
		description = "Trojan:Win64/Trickbot.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8b d0 b9 03 00 00 00 48 8b d8 c7 90 01 01 45 6e 74 65 c7 90 01 02 72 20 74 6f c7 90 01 02 20 43 6f 6e c7 90 01 02 74 72 6f 6c 66 c7 90 01 02 0a 00 90 00 } //01 00 
		$a_03_1 = {48 8b d8 c7 90 01 01 4d 6f 64 75 c7 90 01 02 6c 65 20 68 c7 90 01 02 61 6e 64 6c c7 90 01 02 65 20 30 78 c7 90 01 02 25 30 38 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}