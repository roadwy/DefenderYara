
rule Trojan_Win64_Bafrord_B_dha{
	meta:
		description = "Trojan:Win64/Bafrord.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b8 b2 02 00 00 [0-05] 41 8b d0 66 42 39 04 0a 75 0b 41 83 c0 02 43 80 3c 08 e8 } //1
		$a_03_1 = {48 83 c1 fd [0-14] 4c 03 c1 [0-07] 49 03 c0 [0-07] 48 89 42 08 4c 89 02 [0-07] 48 c7 c2 fd ff ff ff [0-07] ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}