
rule Trojan_BAT_Cryptor_A_MTB{
	meta:
		description = "Trojan:BAT/Cryptor.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {11 00 19 8d 13 00 00 01 25 16 7e 04 00 00 04 a2 25 17 7e 05 00 00 04 a2 25 18 72 5b 00 00 70 a2 0a } //3
		$a_00_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_00_2 = {53 00 74 00 61 00 72 00 74 00 47 00 61 00 6d 00 65 00 } //1 StartGame
		$a_00_3 = {ef 00 bf 00 bd 00 20 00 55 00 70 00 64 00 61 00 74 00 65 00 20 00 52 00 6f 00 6f 00 6d 00 } //1
		$a_00_4 = {52 65 76 65 72 73 65 53 74 72 69 6e 67 44 69 72 65 63 74 } //1 ReverseStringDirect
		$a_00_5 = {50 75 7a 7a 6c 65 5f 4c 6f 61 64 65 72 } //1 Puzzle_Loader
	condition:
		((#a_01_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}