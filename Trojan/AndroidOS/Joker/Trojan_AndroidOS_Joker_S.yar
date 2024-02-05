
rule Trojan_AndroidOS_Joker_S{
	meta:
		description = "Trojan:AndroidOS/Joker.S,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {18 00 ff ff ff ff 00 00 00 00 c0 b0 71 20 8c d6 10 00 0b 00 71 20 8a d6 10 00 0b 00 13 02 20 00 a5 03 00 02 17 05 ff ff 00 00 c0 53 71 20 8a d6 10 00 0b 00 13 07 10 00 a5 07 00 07 17 09 00 00 ff ff c0 97 c5 2b c2 3b c2 7b 84 bc 71 40 84 d6 dc 10 0b 00 a5 03 00 02 c0 53 84 3b 23 b3 b6 2d 12 04 35 b4 14 00 90 07 0c 04 d8 07 07 01 71 40 84 d6 d7 10 0b 00 a5 07 00 02 c0 57 84 78 8e 87 50 07 03 04 d8 04 04 01 28 ed 22 0b ba 2a 70 20 73 df 3b 00 11 0b } //01 00 
		$a_01_1 = {17 00 ff ff 00 00 a0 02 04 00 84 23 8f 32 13 03 10 00 c5 34 c0 04 84 45 8f 54 90 05 02 04 8f 55 13 00 09 00 71 20 8b d6 05 00 0a 05 b0 25 8f 55 b7 24 8f 44 13 00 0d 00 71 20 8b d6 02 00 0a 00 b7 40 8f 00 e0 01 04 05 b7 10 8f 00 13 01 0a 00 71 20 8b d6 14 00 0a 04 81 51 c3 31 81 44 c1 14 c3 34 81 00 c1 04 10 04 } //00 00 
	condition:
		any of ($a_*)
 
}