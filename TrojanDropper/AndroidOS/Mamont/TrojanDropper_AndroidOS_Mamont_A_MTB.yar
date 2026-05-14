
rule TrojanDropper_AndroidOS_Mamont_A_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Mamont.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {0a 0a 6e 10 4b 0c 00 00 0a 0d 82 dd c9 da 82 9d 6e 10 0a 0c 00 00 0a 0e 82 ee c9 ed 71 10 ad 02 0b 00 0a 0e 2d 0e 0e 06 15 0f 80 3f 38 0e 15 00 7f dd 71 30 7e 02 db 0a 0a 0a } //1
		$a_01_1 = {08 13 0f 00 74 08 ae 1b 13 00 52 03 6f 06 44 09 0a 08 b1 93 59 03 6f 06 52 03 7d 06 b0 93 59 03 7d 06 38 0e 5b 00 44 03 1a 08 b1 36 b0 67 3b 07 21 00 7b 63 82 33 6e 10 0a 0c 00 00 } //1
		$a_01_2 = {54 79 40 0b 38 09 0a 00 32 46 08 00 6e 10 67 1b 09 00 0a 09 90 22 09 22 02 09 22 00 38 24 08 00 32 46 06 00 32 b6 04 00 13 1e 05 00 08 22 04 00 54 74 40 0b 38 04 30 00 33 b6 0f 00 02 25 08 00 54 78 43 0b 54 44 43 0b 02 26 0c 00 12 6c 6e 5c de 17 81 94 28 0e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}