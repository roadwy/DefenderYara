
rule Trojan_BAT_AsyncRAT_B_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 0a 73 ?? 00 00 0a 0c 08 06 6f ?? 00 00 0a 00 08 18 6f ?? 00 00 0a 00 08 6f ?? 00 00 0a 0d 09 02 16 02 8e 69 6f ?? 00 00 0a 13 04 08 6f ?? 00 00 0a 00 11 04 13 05 } //2
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
rule Trojan_BAT_AsyncRAT_B_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRAT.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 07 00 00 70 0a 73 17 00 00 0a 73 18 00 00 0a 0b 07 6f 19 00 00 0a 72 c0 dd 0f 70 7e 01 00 00 04 28 03 00 00 06 6f 1a 00 00 0a 26 07 6f 19 00 00 0a 72 22 de 0f 70 7e 01 00 00 04 28 03 00 00 06 6f 1a 00 00 0a 26 07 17 6f 1b 00 00 0a 07 17 8d 14 00 00 01 } //2
		$a_01_1 = {38 35 30 31 64 31 37 32 2d 31 65 62 62 2d 34 36 31 33 2d 38 37 61 34 2d 65 65 66 37 66 32 35 34 36 61 32 37 } //1 8501d172-1ebb-4613-87a4-eef7f2546a27
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}