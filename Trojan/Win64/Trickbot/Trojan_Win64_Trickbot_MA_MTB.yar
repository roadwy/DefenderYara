
rule Trojan_Win64_Trickbot_MA_MTB{
	meta:
		description = "Trojan:Win64/Trickbot.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 44 24 20 89 c1 83 c1 01 89 4c 24 20 48 63 c8 48 8d 05 90 01 04 8a 0c 08 8b 44 24 28 89 c2 83 c2 01 89 54 24 28 48 98 88 4c 04 1c 83 7c 24 28 04 0f 85 90 00 } //01 00 
		$a_01_1 = {0f be 44 24 1c c1 e0 02 0f be 4c 24 1d 83 e1 30 c1 f9 04 01 c8 88 44 24 19 0f be 44 24 1d 83 e0 0f c1 e0 04 0f be 4c 24 1e 83 e1 3c c1 f9 02 01 c8 88 44 24 1a 0f be 44 24 1e 83 e0 03 c1 e0 06 } //00 00 
	condition:
		any of ($a_*)
 
}