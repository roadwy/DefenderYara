
rule Trojan_Win64_Snake_E_dha{
	meta:
		description = "Trojan:Win64/Snake.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_41_0 = {0c b8 66 00 59 21 48 83 c4 60 41 5d c3 48 85 d2 75 0c b8 67 00 59 21 48 83 c4 60 41 5d c3 4d 85 c0 75 0c b8 68 00 59 21 48 83 c4 60 41 5d c3 00 } //1
	condition:
		((#a_41_0  & 1)*1) >=1
 
}