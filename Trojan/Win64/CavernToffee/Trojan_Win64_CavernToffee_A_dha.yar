
rule Trojan_Win64_CavernToffee_A_dha{
	meta:
		description = "Trojan:Win64/CavernToffee.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_43_0 = {c0 4c 8d 35 90 01 04 41 bc 90 01 04 42 80 34 30 90 01 01 48 ff c0 49 3b c4 72 f3 90 00 01 } //1
		$a_33_1 = {4c 8d 3d 90 01 04 42 80 34 38 90 01 01 48 ff c0 48 3d 90 01 01 00 00 00 72 f0 90 00 01 00 34 43 4e 74 41 6c c7 45 90 01 01 6c 6f 63 61 c7 45 90 01 01 74 65 56 69 c7 45 90 01 01 72 74 75 61 c7 45 90 01 } //7680
		$a_65_2 = {c7 45 90 01 01 6f 72 79 00 e8 90 00 00 00 5d 04 00 00 a7 39 06 80 5c 35 00 00 a8 39 06 80 00 00 01 00 08 00 1f 00 54 72 6f 6a 61 6e 3a 57 69 6e 36 34 2f 43 61 76 65 72 6e 54 6f 66 66 65 65 2e 44 21 64 68 61 00 00 01 40 05 82 70 00 } //27649
	condition:
		((#a_43_0  & 1)*1+(#a_33_1  & 1)*7680+(#a_65_2  & 1)*27649) >=3
 
}