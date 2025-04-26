
rule Trojan_Win64_TinyTurla_B_dha{
	meta:
		description = "Trojan:Win64/TinyTurla.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_41_0 = {44 05 42 5c 00 50 00 c7 44 05 46 61 00 72 00 c7 44 05 4a 61 00 6d 00 c7 44 05 4e 65 00 74 00 c7 44 05 52 65 00 72 00 c7 44 05 56 73 00 00 00 0a } //10
		$a_c7_1 = {53 00 59 00 c7 40 04 53 00 54 00 c7 40 08 45 00 4d 00 c7 40 0c 5c 00 43 00 c7 40 10 75 00 72 00 c7 40 14 72 00 65 00 c7 40 18 6e 00 74 00 c7 40 1c 43 00 6f 00 c7 40 20 6e 00 74 00 c7 40 24 72 00 } //30208
	condition:
		((#a_41_0  & 1)*10+(#a_c7_1  & 1)*30208) >=20
 
}