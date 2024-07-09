
rule Backdoor_Linux_Gafgyt_BF_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.BF!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_00_0 = {49 b9 01 01 01 01 01 01 01 01 40 0f b6 d6 4c 0f af ca 49 b8 ff fe fe fe fe fe fe fe 66 66 66 90 66 66 90 66 66 90 } //4
		$a_02_1 = {48 8b 08 48 83 c0 08 4c 89 c2 4c 31 c9 48 01 ca 0f 83 [0-08] 48 31 ca 4c 09 c2 48 ff c2 0f 85 [0-08] 4c 31 c9 4c 89 c2 48 01 ca 0f 83 [0-08] 48 31 ca 4c 09 c2 48 ff c2 0f 85 [0-08] 48 8b 08 48 83 c0 08 4c 89 c2 4c 31 c9 48 01 ca 0f 83 [0-08] 48 31 ca 4c 09 c2 48 ff c2 0f 85 [0-08] 4c 31 c9 4c 89 c2 48 01 ca 73 75 48 31 ca 4c 09 c2 48 ff c2 } //4
		$a_00_2 = {54 53 6f 75 72 63 65 20 45 6e 67 69 6e 65 20 51 75 65 72 79 } //1 TSource Engine Query
		$a_00_3 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //1 npxXoudifFeEgGaACScs
		$a_00_4 = {62 6f 74 2e 63 6f 6d 2f 63 72 61 77 6c 65 72 } //1 bot.com/crawler
		$a_00_5 = {6e 66 31 64 6b 35 61 38 65 69 73 72 39 69 33 32 } //1 nf1dk5a8eisr9i32
	condition:
		((#a_00_0  & 1)*4+(#a_02_1  & 1)*4+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=10
 
}