
rule Trojan_Win64_VibrantPony_A_dha{
	meta:
		description = "Trojan:Win64/VibrantPony.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_42_0 = {bc 00 30 00 00 41 b9 04 00 00 00 ba 00 28 00 00 33 c9 45 8b c4 48 89 45 90 01 01 ff d7 90 00 05 } //5
		$a_49_1 = {46 3c 44 0f be 4d af 45 8b c4 42 8b 54 30 50 41 c1 e1 03 33 c9 ff d7 00 00 5d 04 00 00 8a a7 06 80 5c 2d 00 00 8b a7 06 80 00 00 01 00 08 00 17 00 af 01 44 61 72 6b 54 6f 72 74 69 6c 6c 61 2e } //6400
	condition:
		((#a_42_0  & 1)*5+(#a_49_1  & 1)*6400) >=10
 
}