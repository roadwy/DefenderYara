
rule Trojan_Win64_Snake_A_dha{
	meta:
		description = "Trojan:Win64/Snake.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {48 81 7d 07 a1 72 2d 00 0f 94 c0 84 c0 75 } //00 00 
	condition:
		any of ($a_*)
 
}