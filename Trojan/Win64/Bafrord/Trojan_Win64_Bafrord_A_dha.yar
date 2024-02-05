
rule Trojan_Win64_Bafrord_A_dha{
	meta:
		description = "Trojan:Win64/Bafrord.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 b2 02 00 00 44 8b c1 90 02 02 41 8b d0 66 42 39 04 0a 75 0b 41 83 c0 02 43 80 3c 08 e8 90 00 } //01 00 
		$a_03_1 = {48 83 c1 fd 4c 03 c1 49 03 c0 4c 89 05 90 01 02 00 00 48 89 42 08 4c 89 02 48 8b 0d 90 01 02 00 00 48 c7 c2 fd ff ff ff ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}