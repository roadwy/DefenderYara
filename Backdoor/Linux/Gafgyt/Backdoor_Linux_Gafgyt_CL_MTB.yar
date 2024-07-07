
rule Backdoor_Linux_Gafgyt_CL_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.CL!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {40 be 00 24 3c 60 10 01 7f c4 f3 78 38 63 ab bc 4c c6 31 82 4b ff e8 90 01 01 7f 83 f8 00 41 be 00 08 48 00 0c 55 80 01 00 14 90 00 } //1
		$a_00_1 = {81 23 00 00 7c 0a 48 ae 7c c0 02 78 7c 0a 49 ae 81 63 00 00 7c 0a 58 ae 7c e0 02 78 7c 0a 59 ae 81 23 00 00 7c 0a 48 ae 7d 00 02 78 7c 0a 49 ae 81 63 00 00 7c 0a 58 ae 7c a0 02 78 7c 0a 59 ae 39 4a 00 01 a0 03 00 04 7f 80 50 00 41 9d ff b4 } //1
		$a_00_2 = {48 00 00 44 7d 3f e0 51 41 82 00 7c 7c 1f e8 ae 7f 1e c3 78 7c 9f ea 14 98 18 00 04 34 09 ff ff 41 82 00 64 8b e4 00 01 7c 09 03 78 3b 89 ff ff 38 84 00 01 7f 9c f8 00 3b 18 00 08 41 9c 00 48 3b a4 00 01 38 80 00 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}