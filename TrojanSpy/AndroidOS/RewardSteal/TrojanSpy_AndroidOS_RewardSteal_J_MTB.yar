
rule TrojanSpy_AndroidOS_RewardSteal_J_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/RewardSteal.J!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 b0 06 00 6e 10 12 00 00 00 0c 00 6e 10 39 00 00 00 0c 00 6e 10 3b 00 00 00 0c 00 54 b1 07 00 6e 10 12 00 01 00 0c 01 6e 10 39 00 01 00 0c 01 6e 10 3b 00 01 00 0c 01 6e 10 3a 00 00 00 0a 02 12 03 39 02 5f 00 6e 10 3a 00 01 00 0a 02 38 02 03 00 28 57 } //1
		$a_01_1 = {6e 10 06 00 0d 00 0c 00 38 00 55 00 1a 01 93 00 6e 20 07 00 10 00 0c 01 1f 01 32 00 38 01 4b 00 21 12 12 03 35 23 47 00 46 04 01 03 07 45 1f 05 30 00 71 10 0c 00 05 00 0c 05 6e 10 0d 00 05 00 0c 06 6e 10 0e 00 05 00 0c 07 22 08 2c 00 70 10 3c 00 08 00 1a 09 4c 00 6e 20 3d 00 98 00 0c 08 6e 20 3d 00 68 00 0c 08 6e 10 3e 00 08 00 0c 08 1a 09 4e 00 71 20 0f 00 89 00 22 08 2c 00 70 10 3c 00 08 00 1a 0a 48 00 6e 20 3d 00 a8 00 0c 08 6e 20 3d 00 78 00 0c 08 6e 10 3e 00 08 00 0c 08 71 20 0f 00 89 00 70 20 2f 00 7b 00 d8 03 03 01 28 ba } //1
		$a_01_2 = {63 6f 6d 2f 61 74 6d 2f 63 61 72 64 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //1 com/atm/card/MainActivity
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}