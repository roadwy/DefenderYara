
rule Trojan_Win32_Stoberox_A{
	meta:
		description = "Trojan:Win32/Stoberox.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {b0 7b aa b9 24 00 00 00 51 52 b9 0a 00 00 00 0f 31 69 c0 0d 66 19 00 } //1
		$a_01_1 = {64 a1 30 00 00 00 f7 40 68 70 00 00 00 74 02 ff e0 c3 } //1
		$a_01_2 = {03 7f 3c 0f b7 4f 16 83 7d 0c 00 74 08 81 f1 00 20 00 00 eb 06 81 c9 00 20 00 00 66 89 4f 16 } //1
		$a_01_3 = {c1 e9 02 f3 a5 0f b7 53 06 8d 83 f8 00 00 00 8b 48 10 8b 70 14 8b 78 0c 03 75 e8 03 7d e0 f3 a4 83 c0 28 4a 75 e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}