
rule Backdoor_Linux_Mirai_JK_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.JK!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 43 0c 8d 4c 18 1c 0f b7 51 10 01 c2 8b 41 08 89 53 0c 8b 51 0c 89 43 04 89 53 08 } //1
		$a_03_1 = {57 56 53 8b 5c 24 10 8b 43 0c 3b 43 10 7c ?? be dc 00 00 00 8b 13 bf 00 08 00 00 8d 4b 1c 89 f0 e8 fb 03 00 00 83 f8 00 89 c7 7f ?? 7d ?? 83 f8 fe 74 ?? e8 b8 01 00 00 f7 df 89 38 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Backdoor_Linux_Mirai_JK_MTB_2{
	meta:
		description = "Backdoor:Linux/Mirai.JK!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {76 61 72 2f 63 6f 77 66 66 78 78 6e 61 } //1 var/cowffxxna
		$a_00_1 = {2f 76 61 72 2f 64 6f 77 6e 6c 6f 61 64 65 72 } //1 /var/downloader
		$a_00_2 = {77 35 71 36 68 65 33 64 62 72 73 67 6d 63 6c 6b 69 75 34 74 6f 31 38 6e 70 61 76 6a 37 30 32 66 } //1 w5q6he3dbrsgmclkiu4to18npavj702f
		$a_00_3 = {2f 76 61 72 2f 53 6f 66 69 61 } //1 /var/Sofia
		$a_00_4 = {39 78 73 73 70 6e 76 67 63 38 61 6a 35 70 69 37 6d 32 38 70 } //1 9xsspnvgc8aj5pi7m28p
		$a_00_5 = {4d 6f 6f 62 6f 74 } //1 Moobot
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}