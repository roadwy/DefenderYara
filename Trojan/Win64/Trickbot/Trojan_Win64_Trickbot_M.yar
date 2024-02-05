
rule Trojan_Win64_Trickbot_M{
	meta:
		description = "Trojan:Win64/Trickbot.M,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 f9 01 75 90 02 40 8b 90 01 01 41 33 90 01 01 89 90 01 01 48 83 90 01 01 04 49 83 90 01 01 04 48 83 90 01 01 04 49 3b 90 01 01 49 0f 43 90 01 01 4d 3b 90 01 01 72 e1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}