
rule TrojanDropper_AndroidOS_Badpac_B_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Badpac.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_00_0 = {44 49 06 90 28 1c 79 44 ff f7 77 fc 29 68 41 4a 42 4b 06 1c e2 20 40 00 7b 44 0c 58 7a 44 31 1c 28 1c a0 47 31 1c 02 1c 28 1c ff f7 97 fc 3b 49 04 1c 28 1c 79 44 ff f7 60 fc 39 4a 3a 4b 06 1c 7a 44 7b 44 31 1c 28 1c ff f7 68 fc 06 9b 02 1c 31 1c } //1
		$a_00_1 = {47 49 9b 69 79 44 81 46 20 46 98 47 21 68 44 4a 45 4b d1 f8 c4 71 7a 44 7b 44 06 46 20 46 31 46 b8 47 31 46 02 46 20 46 ff f7 cc fc 23 68 3e 49 9b 69 79 44 80 46 20 46 98 47 21 68 3c 4a } //1
		$a_00_2 = {2b 68 49 49 06 90 9b 69 79 44 28 1c 98 47 29 68 47 4a 47 4b 06 1c e2 20 40 00 0c 58 7b 44 31 1c 7a 44 28 1c a0 47 31 1c 02 1c 28 1c ff f7 cd fc 2b 68 40 49 06 1c 9b 69 79 44 28 1c } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=1
 
}