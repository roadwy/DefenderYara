
rule Trojan_Win32_DCRat_MA_MTB{
	meta:
		description = "Trojan:Win32/DCRat.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_01_0 = {e9 96 21 a3 69 0c 21 3d 24 0c 21 a3 e9 0b 21 fb 3b ce 01 af d8 a2 91 25 14 aa 4b f5 ca 69 fb ed 0a 08 bd 7d be 86 0e f6 c4 5f c2 ef 56 d6 2f bd } //5
		$a_01_1 = {7b 24 bc c0 ac e9 16 d0 c6 34 f5 33 50 f2 bb 1f 75 64 fa a1 94 75 62 b4 23 2f 52 1b 92 8d 84 d7 f9 f7 e9 4d 34 79 5b 13 7a 28 39 64 76 a4 d9 9a } //5
		$a_01_2 = {e0 00 22 01 0b 01 08 00 00 9a 13 00 00 92 1d 00 00 00 00 00 c0 03 55 00 00 20 00 00 00 c0 13 00 00 00 40 00 00 20 00 00 00 02 } //5
		$a_01_3 = {2e 74 68 65 6d 69 64 61 } //1 .themida
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1) >=16
 
}