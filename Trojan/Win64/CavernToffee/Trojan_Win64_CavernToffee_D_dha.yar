
rule Trojan_Win64_CavernToffee_D_dha{
	meta:
		description = "Trojan:Win64/CavernToffee.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_43_0 = {8b c3 48 8d 15 90 01 04 48 8b c8 48 8b f0 e8 90 01 04 48 8b ce 80 31 90 01 01 48 ff c1 48 83 eb 01 75 f4 90 00 01 } //1
		$a_43_1 = {65 61 c7 45 90 01 01 74 65 54 68 c7 45 90 01 01 72 65 61 64 88 5d 90 01 01 e8 90 01 04 48 21 5c 24 90 01 01 4c 8b cf 21 5c 24 90 01 01 4c 8b c6 33 d2 33 c9 ff d0 48 8b d8 48 83 f8 ff 74 1c 48 8d 4d 90 } //23296
	condition:
		((#a_43_0  & 1)*1+(#a_43_1  & 1)*23296) >=2
 
}