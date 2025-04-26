
rule Trojan_Win64_Alureon_gen_G{
	meta:
		description = "Trojan:Win64/Alureon.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 81 e1 00 e0 ff ff 76 1f 66 90 66 81 39 4d 5a 75 0d 48 63 41 3c 81 3c 08 50 45 00 00 74 09 48 81 e9 00 10 00 00 75 e3 } //1
		$a_01_1 = {83 7e 04 ff 74 71 8b 7e 10 8b 06 89 6e 08 49 03 fc 85 c0 c7 46 04 37 13 c3 cd } //1
		$a_01_2 = {41 8b 49 0c 41 8b 51 08 41 81 61 0c 0f 08 00 f0 48 8b c1 4c 8b c2 48 25 00 00 00 f8 41 81 e0 ff ff 7f 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}