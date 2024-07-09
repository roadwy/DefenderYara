
rule Trojan_Win64_MoonBounce_A{
	meta:
		description = "Trojan:Win64/MoonBounce.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 63 58 3c be 00 20 00 00 45 8b cc 48 03 d8 44 8b c6 8b 53 50 48 8b 4b 30 41 ff 56 10 } //1
		$a_01_1 = {8b 53 50 45 8b cc 44 8b c6 33 c9 41 ff 56 10 } //1
		$a_01_2 = {b8 89 88 88 88 f7 e9 03 d1 c1 fa 03 8b c2 c1 e8 1f 03 d0 42 8d 04 82 8b c8 c1 e8 03 } //1
		$a_03_3 = {48 8d 83 e0 01 00 00 4c 8d 8b c0 01 00 00 48 89 ?? ?? ?? 4c 8d 83 80 01 00 00 48 8d 93 1c 01 00 00 48 8b cb 48 89 ?? ?? ?? e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}