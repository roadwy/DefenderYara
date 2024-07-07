
rule Backdoor_Linux_Gafgyt_CS_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.CS!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {d9 4a 1a 3a ec 8a b9 37 e1 2b 1b c8 69 15 26 8b e3 d5 df 20 70 bb d9 31 3c 17 50 cd 67 76 32 f6 f2 9a f3 07 2f cc b5 b7 4a b6 69 8f a1 00 32 ad f4 90 d6 b3 94 87 39 5b 31 d4 ff af e9 6b 8e a7 5d 56 46 99 aa f7 50 3d 27 aa 7b e0 f4 fe 8c f0 } //1
		$a_00_1 = {08 8e bf bd 62 7b ec a2 0c 73 3f 37 30 20 ea ce dd 88 06 9e } //1
		$a_03_2 = {1a 03 00 00 68 2a df 69 55 8e 64 30 c7 73 9b 8b 3a 0a 6b 93 e5 06 2d 2c d6 3c 12 98 a9 76 90 01 02 56 52 c7 34 eb 22 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}