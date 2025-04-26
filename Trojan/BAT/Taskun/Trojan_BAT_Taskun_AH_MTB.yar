
rule Trojan_BAT_Taskun_AH_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_00_0 = {01 70 03 11 04 18 6f 3a 00 00 0a 28 3b 00 00 0a 28 3c 00 00 0a 04 08 6f 3d 00 00 0a 28 3e 00 00 0a 6a 61 b7 28 3f 00 00 0a 28 40 00 00 0a 13 05 07 11 05 6f 41 00 00 0a 26 08 04 6f 39 00 00 0a 17 da fe 01 13 06 11 06 2c 04 } //10
		$a_80_1 = {48 65 62 72 65 77 4e 75 6d 62 65 72 50 61 72 73 69 6e 67 } //HebrewNumberParsing  3
		$a_80_2 = {48 69 65 72 61 63 68 69 63 61 6c 46 6f 72 65 63 61 73 74 69 6e 67 } //HierachicalForecasting  3
		$a_80_3 = {58 4f 52 5f 44 65 63 72 79 70 74 } //XOR_Decrypt  3
		$a_80_4 = {54 69 6d 65 73 65 72 69 65 73 } //Timeseries  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}