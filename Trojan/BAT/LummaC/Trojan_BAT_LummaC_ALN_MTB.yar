
rule Trojan_BAT_LummaC_ALN_MTB{
	meta:
		description = "Trojan:BAT/LummaC.ALN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {d4 f6 e4 9c 38 10 77 6b b3 ce 36 30 ba a6 d0 92 53 36 59 62 0f 33 e3 f4 56 94 18 14 bb 04 e8 26 52 4f 29 92 e8 4f f1 18 82 9c a6 } //1
		$a_01_1 = {69 00 6e 00 74 00 65 00 67 00 72 00 61 00 74 00 65 00 20 00 6e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 20 00 72 00 65 00 64 00 20 00 69 00 64 00 65 00 61 00 20 00 79 00 6f 00 75 00 20 00 73 00 68 00 65 00 20 00 73 00 6f 00 6c 00 76 00 65 00 20 00 69 00 6e 00 73 00 70 00 69 00 72 00 65 00 20 00 76 00 69 00 73 00 69 00 6f 00 6e 00 20 00 72 00 65 00 64 00 } //2 integrate network red idea you she solve inspire vision red
		$a_01_2 = {4c 00 69 00 61 00 6d 00 42 00 72 00 69 00 74 00 61 00 69 00 6e 00 56 00 69 00 6f 00 6c 00 65 00 74 00 4e 00 61 00 74 00 68 00 61 00 6e 00 2e 00 65 00 78 00 65 00 52 00 4f 00 44 00 } //3 LiamBritainVioletNathan.exeROD
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3) >=6
 
}