
rule Backdoor_Linux_Mirai_DS_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.DS!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {00 ca e6 e7 e7 ec ea fd e0 e6 e7 b3 a9 c2 ec ec f9 a4 c8 e5 e0 ff ec 89 00 bb b9 a8 dc d3 9b 99 93 95 8c d3 c3 9e 9d 8e 99 da 95 8c 8a c1 c8 da 8e 99 8f c1 cd ca dc b4 a8 a8 ac d3 cd d2 cc fc 00 24 29 20 20 23 3b 23 3e 20 28 4c 00 } //1
		$a_00_1 = {42 33 55 57 59 6d 4e 4d 74 43 72 66 50 67 63 75 4b 7a 32 34 62 53 73 4c 78 37 41 58 51 4a 47 61 68 39 38 65 77 69 76 46 54 4f 45 52 64 5a 2f 6c 31 49 36 6e 6a 35 48 70 6b 79 56 30 6f 71 2e 00 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}