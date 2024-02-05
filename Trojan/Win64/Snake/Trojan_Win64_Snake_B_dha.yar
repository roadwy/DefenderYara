
rule Trojan_Win64_Snake_B_dha{
	meta:
		description = "Trojan:Win64/Snake.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_43_0 = {d2 41 b8 00 80 00 00 90 02 06 ff 15 90 02 03 ff 90 01 03 4c 8d 44 24 90 01 01 48 8d 54 24 90 01 01 8b 90 01 01 e8 90 01 02 ff ff 85 c0 74 90 03 01 01 bc bd 90 00 00 } //00 5d 
	condition:
		any of ($a_*)
 
}